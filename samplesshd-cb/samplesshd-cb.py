# -*- coding: utf-8 -*-
##############importation des fonctions########################
import sys
import os
import io
import pylibssh

##############declaration de variables##############
USER = "myuser"
PASSWORD = "mypassword"
authenticated=False
tries = 0
channel = None
session= None
sshbind = None
mainloop = None

#############definition des fonction #############
class myChannelCallbacks(pylibssh.ChannelCallbacks):
    def requestPty(self, term, width, height, pxwidth, pxheight):
        print "allocated pty"
        return pylibssh.api.SSH_OK
    def requestShell(self):
        print "allocated shell"
        return pylibssh.api.SSH_OK

class myServerCallbacks(pylibssh.ServerCallbacks):
    def __init__(self, session):
        self.session = session
    def authPassword(self, user, password):
        print "Authenticating user " + user + " pwd " + password
        global tries
        global authenticated
        tries = tries + 1
        if(user == USER and password == PASSWORD):
            authenticated = True
            print "Authenticated"
            return pylibssh.api.SSH_AUTH_SUCCESS
        if (tries >= 3):
            print "Too many authentication tries\n"
            session.disconnect()
            error = True
            return pylibssh.api.SSH_AUTH_DENIED
        return pylibssh.api.SSH_AUTH_DENIED
    def authGssapiMic(self, user):
        print "Authenticating user" + user + " with gssapi"
        print "authenticated !"
        authenticated = True
        return pylibssh.api.SSH_AUTH_SUCCESS
    def channelOpenSessionRequest(self):
        global channel
        channel = pylibssh.Channel(self.session)
        channel.setCallbacks(myChannelCallbacks(channel))
        return channel
  
def setOpts(sshbind):
    sshbind.setOption(pylibssh.SSH_BIND_OPTIONS_BINDPORT_STR, "2222")
    sshbind.setOption(pylibssh.SSH_BIND_OPTIONS_DSAKEY, "sshd_dsa")
    sshbind.setOption(pylibssh.SSH_BIND_OPTIONS_RSAKEY, "sshd_rsa")
    sshbind.setOption(pylibssh.SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3")
    sshbind.setOption(pylibssh.SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0")

def main():
#    buffer_len = 2048
    sshbind=pylibssh.Bind()
    session=pylibssh.ServerSession()
    setOpts(sshbind)
    
    sshbind.listen()
    sshbind.accept(session)
    cb = myServerCallbacks(session)
    session.setCallbacks(cb)
    session.handleKeyExchange()
    session.setAuthMethods(pylibssh.api.SSH_AUTH_METHOD_PASSWORD | pylibssh.api.SSH_AUTH_METHOD_GSSAPI_MIC)
    mainloop = pylibssh.Event()
    mainloop.addSession(session)

    while ((not authenticated) or (channel is None)):
    	mainloop.doPoll()

    print"Authenticated and got a channel\n"
    print channel
    channel.write("Welcome to the ssh-o-matic !\r\n")
    name = ""
    channel.write("What is your name ? ")
    while name.find("\n") < 0:
        r = channel.read(10)
        r = r.replace("\x0D", "\r\n")
        name += r
        channel.write(r)
    name = name.split("\r")[0].split("\n")[0]
    channel.write("Hello, " + name + "!\r\n")
    while True:
        r= channel.read(10)
        r = r.replace("\x0D", "\r\n")
        channel.write(r)
  
    while (i>0):
        session.disconnect()
        session.ssh_bind_free(sshbind)
        session.ssh_finalize()
    return 0



main()
