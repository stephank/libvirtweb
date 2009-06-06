#!/usr/bin/env python

from twisted.internet import reactor


# Setup twisted logging
from twisted.python import log
import sys
log.startLogging(sys.stdout)


# Start up the common part
import common
common.init(reactor)


# CherryPy-in-Twisted setup
import cherrypy
cherrypy.config.update({
   'environment': 'embedded',
   'log.screen': True
})
# We need to unsubscribe the CherryPy server to prevent a port conflict
cherrypy.server.unsubscribe()
# Start CherryPy internals
cherrypy.engine.start()
# Make sure we shut down CherryPy
reactor.addSystemEventTrigger('after', 'shutdown', cherrypy.engine.exit)


# The RFB proxy
import rfbproxy
factory = rfbproxy.getfactory(reactor)
reactor.listenTCP(5900, factory)


# The website
from twisted.internet import ssl
import virtweb
try:
   factory = virtweb.getfactory(reactor)
except ValueError, e:
   print str(e)
   reactor.callLater(0, reactor.stop)
else:
   tlsctxFactory = ssl.DefaultOpenSSLContextFactory('server.key', 'server.cert', ssl.SSL.TLSv1_METHOD)
   reactor.listenSSL(8443, factory, tlsctxFactory)


# The main loop
reactor.run()

