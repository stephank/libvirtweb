import os, base64, binascii
from twisted.python import log, threadable
from Crypto.Cipher import AES


class RFBCookieContainer(object):
   """Container for cookies that are sent to the browser and then received in the RFB connection."""

   TIMEOUT = 300

   synchronized = ['_expire', 'create', 'pop']

   def __init__(self, reactor):
      self.reactor = reactor
      self.cookies = {}

   def _expire(self, cookie):
      try:
         del self.cookies[cookie]
         log.msg("Forgotten cookie: %s" % binascii.hexlify(cookie))
      except KeyError:
         pass

   def create(self, value):
      """Create a random cookie and associate the give value with it."""

      cookie = os.urandom(16)
      timer = self.reactor.callLater(self.TIMEOUT, self._expire, cookie)
      self.cookies[cookie] = (value, timer)
      log.msg("Storing cookie: %s" % binascii.hexlify(cookie))
      return cookie

   def pop(self, challenge, attempt):
      """Find a cookie, and pop it's value from the container.

      Check if the given attempt, based on the given challenge, matches any of the cookies.
      If it does, the cookie is removed from the container, and the value returned."""

      # The client encrypts the challenge with the cookie. We can't deduce the cookie
      # from the encrypted challenge, so we'll just have to try with each and see if one matches.
      for cookie, item in self.cookies.iteritems():
         aesobj = AES.new(cookie, AES.MODE_ECB)
         expected = aesobj.encrypt(challenge)
         if attempt == expected:
            value, timer = item
            del self.cookies[cookie]
            timer.cancel()
            log.msg("Retrieved cookie: %s" % binascii.hexlify(cookie))
            return cookie, value

threadable.synchronize(RFBCookieContainer)


cookies = None

def init(reactor):
   global cookies
   cookies = RFBCookieContainer(reactor)

