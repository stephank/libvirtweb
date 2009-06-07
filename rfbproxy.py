from twisted.internet import protocol, defer
from twisted.conch.ssh import forwarding
from twisted.python import log
from Crypto.Cipher import AES
import os, struct, common, binascii
import sshtunnel


# We use the non-standard 0x72 security type in this code, which
# is also implemented in the customized TightVNC viewer. It's basically
# the same as the old DES-based authentication, but with AES.

# The main reason for this is because DES sucks, and especially so in
# the VNC authentication case, because they use a slightly modified DES
# algorithm. The net result is that PyCrypto can't cope.


class RFBState(object):
   """The states our RFBProxyServer and RFBProxyClient instances can be in."""
   ERROR = -1
   PROTOCOL_HANDSHAKE = 1
   SECURITY_HANDSHAKE = 2
   AUTHENTICATION = 3
   SETUP = 4
   ESTABLISHED = 5


class RFBProxyServer(protocol.Protocol):
   """The server-side of our RFB proxy.

   This simple RFB proxy implements part of the version 3.8 RFB protocol spec.
   Specifically, it handles just the protocol handshake, security handshake and
   authentication parts, before simply becoming a pass-through for both ends.

   This server-side protocol class also encrypts the stream to the viewer using
   AES, past the authentication stage."""

   @staticmethod
   def varstring(text):
      """Helper method for sending an RFB variable-length string."""
      return struct.pack('!l', len(text)) + text

   def connectionMade(self):
      self.state = RFBState.PROTOCOL_HANDSHAKE
      self.buffer = ""
      self.transport.write("RFB 003.008\n")

   def dataReceived(self, data):
      if self.state == RFBState.ESTABLISHED:
         self.outdata(data)
         return

      self.buffer += data

      if self.state == RFBState.PROTOCOL_HANDSHAKE:
         self.handshakeStage()
      elif self.state == RFBState.SECURITY_HANDSHAKE:
         self.securityStage()
      elif self.state == RFBState.AUTHENTICATION:
         self.authenticationStage()

   def handshakeStage(self):
      """Handle the handshake response from the client, and start the security type selection."""
      parts = self.buffer.split('\n', 1)
      if len(parts) == 2:
         version, self.buffer = parts
         # Must have a protocol version 8 client
         if version != "RFB 003.008":
            # 0 security types, error string
            self.transport.write("\x00" + self.varstring("Unsupported protocol version"))
            self.transport.loseConnection()
         else:
            log.msg("New VNC client connection")
            self.state = RFBState.SECURITY_HANDSHAKE
            # 1 security type supported: AES cookie authentication (0x72)
            self.transport.write("\x01\x72")

      elif len(self.buffer) > 12:
         # Protocol version handshake is never this long
         self.transport.loseConnection()

   def securityStage(self):
      """Handle the security type selection from the client, and send the challenge."""
      if len(self.buffer) < 1:
         return

      security, self.buffer = self.buffer[:1], self.buffer[1:]
      # Excepting confirmation of AES cookie authentication
      if security != '\x72':
         log.msg("Client failed to negotiate authentication")
         # Failure code, error description
         self.transport.write(struct.pack('!l', 1) + self.varstring("Unsupported security type"))
         self.transport.loseConnection()
      else:
         self.state = RFBState.AUTHENTICATION
         self.challenge = os.urandom(16)
         self.transport.write(self.challenge)

   def authenticationStage(self):
      """Handle the challenge response for the client, and start the proxy connection."""
      if len(self.buffer) < 32:
         return

      attempt, iv, self.buffer = self.buffer[:16], self.buffer[16:32], self.buffer[32:]
      # Check which cookie to use
      cookie, info = common.cookies.pop(self.challenge, attempt)
      if info is None:
         log.msg("Client failed to authenticate")
         # Send a dummy IV
         self.transport.write(16 * '\x00')
         # Failure code, error description
         self.transport.write(struct.pack('!l', 1) + self.varstring("Authentication failed"))
         self.transport.loseConnection()
         return

      # Take the input stream IV, and generate an IV for the output stream
      aesobj = AES.new(cookie, AES.MODE_ECB)
      iniv = aesobj.decrypt(iv)
      outiv = os.urandom(16)
      encryptediv = aesobj.encrypt(outiv)
      self.transport.write(encryptediv)

      # Prepare the AES instances for encryption
      self.inaes = AES.new(cookie, AES.MODE_CFB, iniv, segment_size=8)
      self.outaes = AES.new(cookie, AES.MODE_CFB, outiv, segment_size=8)

      # Post-pone authentication response until finishSetup
      del self.challenge
      self.state = RFBState.SETUP
      connectVNC(self, info).addCallbacks(self.finishSetup, self.bail)

   def bail(self, reason):
      """Send and authentication failure to the client when our proxy connection fails."""
      log.msg("Proxy client connection failed.")
      # Failure code, error description
      self.transport.write(struct.pack('!l', 1) + self.varstring("Proxy connection failed"))
      self.transport.loseConnection()
      self.state = RFBState.ERROR

   def finishSetup(self, clientproto):
      """Send a successful authentication response to the client."""
      self.clientproto = clientproto
      # Success response
      self.state = RFBState.ESTABLISHED
      self.transport.write('\x00\x00\x00\x00')
      if self.buffer:
         self.outdata(self.buffer)
      del self.buffer
      log.msg("Client connection setup complete")

   def indata(self, data):
      """While the connection is established, encrypt and proxy data from the server."""

      self.transport.write(self.outaes.encrypt(data))

   def outdata(self, data):
      """While the connection is established, decrypt and proxy data from the client."""

      self.clientproto.transport.write(self.inaes.decrypt(data))

   def connectionLost(self, reason):
      if hasattr(self, 'clientproto'):
         self.clientproto.transport.loseConnection()

   def proxyConnectionLost(self, reason):
      self.transport.loseConnection()


class RFBProxyServerFactory(protocol.ServerFactory):
   """ServerFactory for the RFBProxyServer."""
   protocol = RFBProxyServer


class RFBProxyClient(protocol.Protocol):
   """The client-side of our RFB proxy.

   This runs on top of a TCP transport, but also on top of a SSHChannel.
   Like the RFBProxyServer, it handles only the protocol handshake, security
   handshake and authentication stages. For the authentication stage, it expects
   a server that has authentication turned off."""

   #
   # Fairly generic stuff
   #

   def connectionMade(self):
      self.state = RFBState.PROTOCOL_HANDSHAKE
      self.buffer = ""

   def dataReceived(self, data):
      if self.state == RFBState.ESTABLISHED:
         self.rawRfbData(data)
         return

      self.buffer += data

      if self.state == RFBState.PROTOCOL_HANDSHAKE:
         self.handshakeStage()
      elif self.state == RFBState.SECURITY_HANDSHAKE:
         self.securityStage()
      elif self.state == RFBState.AUTHENTICATION:
         self.authenticationStage()

   def handshakeStage(self):
      """Handle the handshake request from the server, and send a response."""
      parts = self.buffer.split('\n', 1)
      if len(parts) == 2:
         version, self.buffer = parts
         # Must have a protocol version 8 server
         if version != "RFB 003.008":
            self.transport.loseConnection()
         else:
            self.state = RFBState.SECURITY_HANDSHAKE
            self.transport.write("RFB 003.008\n")

      elif len(self.buffer) > 12:
         # Protocol version handshake is never this long
         self.transport.loseConnection()

   def securityStage(self):
      """Handle the security selection request from the server, and send a response."""
      if len(self.buffer) < 1:
         return

      size = ord(self.buffer[0])
      if size == 0:
         log.msg("Server did not accept protocol handshake")
         self.transport.loseConnection()
         return
      elif len(self.buffer) >= size + 1:
         versions, self.buffer = self.buffer[1:size+1], self.buffer[size+1:]
         # Excepting 'None' security type (0x01)
         if not '\x01' in versions:
            log.msg("Server does not advertise blank authentication")
            self.transport.loseConnection()
            return
         self.state = RFBState.AUTHENTICATION
         self.transport.write('\x01')

   def authenticationStage(self):
      """Handle the security response from the server."""
      if len(self.buffer) < 4:
         return

      result, self.buffer = self.buffer[:4], self.buffer[4:]
      # Excepting 0 result, OK
      if result != '\x00\x00\x00\x00':
         log.msg("Server reported authentication failure")
         self.transport.loseConnection()
         return
      log.msg("VNC connection to server established")
      self.state = RFBState.ESTABLISHED
      self.loggedIn()
      if self.buffer:
         self.rawRfbData(self.buffer)
      del self.buffer

   #
   # Proxy stuff
   #

   def __init__(self, parent, deferred):
      self.parent = parent
      self.deferred = deferred

   def loggedIn(self):
      self.deferred.callback(self)
      del self.deferred

   def loginFailure(self, reason):
      self.deferred.errback(reason)
      del self.deferred

   def rawRfbData(self, data):
      self.parent.indata(data)

   def connectionLost(self, reason):
      self.parent.proxyConnectionLost(reason)


class RFBProxyClientFactory(protocol.ClientFactory):
   """ClientFactory for the RFBProxyClient."""
   protocol = RFBProxyClient

   def __init__(self, parent, deferred):
      self.parent = parent
      self.deferred = deferred

   def buildProtocol(self, addr):
      p = self.protocol(self.parent, self.deferred)
      del self.deferred
      p.factory = self
      return p

   def clientConnectionFailed(self, connector, reason):
      self.deferred.errback(connector)
      del self.deferred


def connectVNC(parent, info):
   """Use the info dictionary to start up a VNC connection on top of the proper transport.

   The info dictionary is created by the virtweb site, and stored alongside a cookie
   in the common module."""

   # Thus, when reading this piece of code, one might say that it flows a bit like:
   # ajax_console -> black voodoo magic -> connectVNC

   d = defer.Deferred()
   def genericfailure(failure):
      d.errback(failure)
      return failure

   # FIXME: Dirty nasty deferreds being passed around in inappropriate places
   reactor = parent.transport.reactor
   factory = RFBProxyClientFactory(parent, d)

   # Should we tunnel over SSH?
   if 'sshhost' in info:
      sshtunnel.ammendfromconfig(info)

      def sshconnect(service):
         protocol = factory.buildProtocol(None)
         transport = sshtunnel.RFBSSHChannel(protocol)
         request = forwarding.packOpen_direct_tcpip(
               (info['vnchost'], info['vncport']),    # The remote endpoint
               ('localhost', 0))                      # The local endpoint
         log.msg("Opening VNC connection to %s:%d over SSH tunnel" % (info['vnchost'], info['vncport']))
         service.openChannel(transport, request)
         return service

      sshtunnel.getservice(reactor, info).addCallbacks(sshconnect, genericfailure)

   # We shouldn't tunnel, set up a regular connection
   else:
      log.msg("Attempting VNC connection to %s:%d" % (info['vnchost'], info['vncport']))
      reactor.connectTCP(info['vnchost'], info['vncport'], factory)

   return d


def getfactory(reactor):
   return RFBProxyServerFactory()

