import os, os.path, base64
from twisted.python import log
from twisted.internet import defer, protocol
from twisted.conch import error
from twisted.conch.ssh import transport, userauth, connection, channel
from Crypto.PublicKey import RSA
from pyasn1.codec.der import decoder as derdecoder
from pyasn1.error import PyAsn1Error

try:
   from config import FINGERPRINT
except ImportError:
   FINGERPRINT = None


# Cache of SSHConnections, so they can be shared
services = {}


class RFBSSHClientTransport(transport.SSHClientTransport):
   def __init__(self, info):
      self.info = info

   def verifyHostKey(self, hostKey, fingerprint):
      if fingerprint != FINGERPRINT:
         return defer.fail(error.ConchError('Incorrect fingerprint received'))
      else:
         return defer.succeed(1)

   def connectionSecure(self):
      self.requestService(RFBSSHUserAuthClient(self.info))


class RFBSSHUserAuthClient(userauth.SSHUserAuthClient):
   def __init__(self, info):
      self.info = info
      userauth.SSHUserAuthClient.__init__(self,
            info['sshuser'], RFBSSHConnection(self.info))

      self.publicstr = None
      self.rsaobj = None
      self.loadKey()

   def loadKey(self):
      if 'sshkey' not in self.info:
         return

      key = os.path.expanduser(self.info['sshkey'])
      log.msg("Reading private key from: %s" % key)

      # Let's read the private key file!
      # FIXME: Support more algorithms besides RSA
      found = False
      keylines = []
      for line in open(key, 'r'):
         if not found:
            if line == '-----BEGIN RSA PRIVATE KEY-----\n':
               found = True
               continue
         if found:
            if line == '-----END RSA PRIVATE KEY-----\n':
               break
            else:
               keylines.append(line)
      else:
         # We shouldn't fall through, it mines we didn't find
         # the end-line or no key at all.
         log.msg("Private key file is invalid.")
         return

      # Now, let's read the public key file!
      public = '%s.pub' % key
      log.msg("Reading public key from: %s" % public)
      public = open(public, 'r').readline().split()
      public = base64.b64decode(public[1])

      # Join the lines and base64 decode
      key = base64.b64decode(''.join([line.strip() for line in keylines]))
      del keylines

      # DER decode
      try:
         key = derdecoder.decode(key)
      except PyAsn1Error, e:
         log.msg("Error decoding DER private key: %s" % str(e))
         return

      try:
         # Appears to be a sequence of RSAPrivateKeys, so take the first
         key = key[0]

         # Expecting a version 0 RSAPrivateKey
         if key[0] != 0:
            log.msg("Private key version not supported.")
            return

         # The indices of RSAPrivateKey and the RSA.construct parameters mostly
         # line up, except for 'u'.
         key = tuple([long(x) for x in key[1:6]])
         key = RSA.construct(key)

      except IndexError:
         log.msg("Private key structure unrecognized.")
         return

      # We came all the way to the end, store these now
      self.rsaobj = key
      self.publicstr = public

   def getPublicKey(self):
      return self.publicstr

   def getPrivateKey(self):
      return defer.succeed(self.rsaobj)


class RFBSSHConnection(connection.SSHConnection):
   def __init__(self, info):
      connection.SSHConnection.__init__(self)
      self.info = info

   def serviceStarted(self):
      global services

      log.msg("SSH connection established")

      # The key used in the SSHConnection cache
      self.key = '%s@%s:%s' % (self.info['sshuser'], self.info['sshhost'], self.info['sshport'])

      # Get the deferred
      deferred = services[self.key]

      # Update the cache dict to contain ourselves
      services[self.key] = self

      # Fire the deferred
      deferred.callback(self)

   def serviceStopped(self):
      global services

      log.msg("SSH connection closed")

      # Remove ourselves from the cache dict
      del services[self.key]


class RFBSSHChannel(channel.SSHChannel):
   name = 'direct-tcpip'

   def __init__(self, protocol):
      channel.SSHChannel.__init__(self)
      self.protocol = protocol

   def openFailed(self, reason):
      log.err(reason)

   def channelOpen(self, data):
      self.protocol.makeConnection(self)

   def dataReceived(self, data):
      if not self.protocol: return
      self.protocol.dataReceived(data)

   def eofReceived(self):
      self.loseConnection()

   def closed(self):
      if not self.protocol: return
      self.protocol.connectionLost(None)


def getservice(reactor, info):
   """Get an SSHConnection instance for the given info dictionary. Returns a deferred."""

   global services

   # The key used in the SSHConnection cache
   key = '%s@%s:%s' % (info['sshuser'], info['sshhost'], info['sshport'])

   if key in services:
      service = services[key]
      if isinstance(service, connection.SSHConnection):
         # If we already have a connection, return it immediately.
         return defer.succeed(service)
      else:
         # Otherwise, it's a deferred, and we return it verbatim.
         return service

   log.msg("Attempting SSH connection to %s:%d" % (info['sshhost'], info['sshport']))
   deferred = defer.Deferred()
   services[key] = deferred
   protocol.ClientCreator(reactor, RFBSSHClientTransport, info
         ).connectTCP(info['sshhost'], info['sshport']
         ).addErrback(deferred.errback)
   return deferred


def ammendfromconfig(info):
   """Ammend the SSH parameters in the info dictionary with values from ssh_config."""

   try:
      found = 0   # Find the matching Host line
      for line in open(os.path.expanduser("~/.ssh/config")):
         parts = line.strip().split()
         if not parts: continue
         if found == 0:
            if parts[0].lower() == 'host' and parts[1] == info['sshhost']:
               found = 1
         elif found == 1:
            if parts[0].lower() == 'host':
               break    # We've reached the next Host line, stop here
            elif parts[0].lower() == 'hostname':
               info['sshhost'] = parts[1]
            elif parts[0].lower() == 'port':
               info['sshport'] = int(parts[1])
            elif parts[0].lower() == 'user':
               if 'sshuser' not in info:  # URI takes preference
                  info['sshuser'] = parts[1]
            elif parts[0].lower() == 'identityfile':
               info['sshkey'] = os.path.expanduser(parts[1])
      # Take the username from the environment if we still don't have it
      if not 'sshuser' in info:
         info['sshuser'] = os.environ['USER']
   except IOError:
      pass

