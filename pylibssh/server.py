from . import api
from api import lib
from codes import *
from session import Session, SessionCallbacks
from common import SSHException, cstring

class ServerCallbacks(SessionCallbacks):
    """Callbacks specific to server sessions"""
    def authNone(self, user):
        return SSH_AUTH_DENIED
    def authPassword(self, user, password):
        print "User " + user + " password " + password
        return SSH_AUTH_DENIED
    def authGssapiMic(self, user, principal):
        print "User " + user + " principal " + principal
        return SSH_AUTH_DENIED
    def authPubkey(self, user, pubkey, signature_state):
        print "User " + user + " pubkey"
        return SSH_AUTH_DENIED
    def channelOpenSessionRequest(self):
        return None

class ServerSession(Session):
    """Methods applying only to server sessions"""
    def handleKeyExchange(self):
        rc = lib.ssh_handle_key_exchange(self.session)
        self.check(rc)
        return rc
    def setAuthMethods(self, authmethods):
        lib.ssh_set_auth_methods(self.session, authmethods)
    def setCallbacks(self, cb):
        self.servercallbacks = api.ssh_server_callbacks_struct()
        self.servercallbacks.auth_none_function = _auth_none_cb_object
        self.servercallbacks.auth_password_function = _auth_password_cb_object
        self.servercallbacks.auth_gssapi_mic_function = _auth_gssapi_mic_cb_object
        self.servercallbacks.auth_pubkey_function = _auth_pubkey_cb_object
        self.servercallbacks.channel_open_request_session_function = _channel_open_request_session_cb_object
        self.servercallbacks.size = ctypes.sizeof(api.ssh_server_callbacks_struct)
        self.servercallbacks.userdata = cb
        lib.ssh_set_server_callbacks(self.session, self.servercallbacks)
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
        super(ServerSession, self).setCallbacks(cb)
    def getGssapiCreds(self):
        return lib.ssh_gssapi_get_creds(self.session)
#******************************************************
def _auth_password_function(sessionp, userp, passwordp, userargp):
    return userargp.authPassword(str(userp), str(passwordp))
def _auth_gssapi_mic_function(sessionp, userp, principalp, userargp):
    return userargp.authGssapiMic(str(userp), str(principalp))
def _auth_none_function(sessionp, userp, userargp):
    return userargp.authNone(str(userp))
def _auth_pubkey_function(sessionp, userp, keyp, sig_state, userargp):
    return userargp.authPubkey(str(userp), Key(keyp), sig_state)

def _channel_open_request_session_function(sessionp, userargp):
    chan = userargp.channelOpenSessionRequest()
    if(chan is None):
        return None
    else:
        return chan.channel
_auth_none_cb_object = api.auth_none_cb(_auth_none_function)
_auth_password_cb_object = api.auth_password_cb(_auth_password_function)
_auth_gssapi_mic_cb_object = api.auth_gssapi_mic_cb(_auth_gssapi_mic_function)
_auth_pubkey_cb_object = api.auth_pubkey_cb(_auth_pubkey_function)
_channel_open_request_session_cb_object = api.channel_open_request_session_cb(
                                      _channel_open_request_session_function)
 
def _auth_function(sessionp, promptp, bufp, echop, verifyp, userargp):
    pass
    #return userargp.auth(str(bufp), str(verifyp))
def _log_function(sessionp, priorityp, messagep, userargp):
    userargp.log(priorityp, str(messagep))
def _connect_status_function (userargp, statusp):
    userargp.connectStatus(statusp)
def _global_request_function(sessionp, messagep, userargp):
    userargp.globalRequest(messagep)
def _channel_open_request_x11_function(sessionp, originator, originator_port, userargp):
    chan = userargp.channelOpenX11Request(str(originator),originator_port)
    if(chan is None):
        return None
    else:
        return chan.channel

_auth_cb_object = api.auth_cb(_auth_function)
_log_cb_object = api.log_cb(_log_function)
_connect_status_cb_object = api.connect_status_cb(_connect_status_function)
_global_request_cb_object = api.global_request_cb(_global_request_function)
_channel_open_request_x11_cb_object = api.channel_open_request_x11_cb(
                                      _channel_open_request_x11_function)


class Bind(object):
    bind = None
    def __init__(self):
        self.bind = lib.ssh_bind_new()
    def listen(self):
        rc = lib.ssh_bind_listen(self.bind)
        self.check(rc)
        return rc
    def __del__(self):
        if(self.bind is not None):
            lib.ssh_bind_free(self.bind)
            self.bind=None
    def accept(self, session, fd = None):
        if (fd != None):
            rc = lib.ssh_bind_accept_fd(self.bind, session.session, fd)
        else:
            rc = lib.ssh_bind_accept(self.bind, session.session)
        self.check(rc)
        return rc
    def setOption(self, option, value):
        if (option == SSH_BIND_OPTIONS_BINDADDR or option == SSH_BIND_OPTIONS_BINDPORT_STR
            or option == SSH_BIND_OPTIONS_HOSTKEY or option == SSH_BIND_OPTIONS_DSAKEY
            or option == SSH_BIND_OPTIONS_RSAKEY or option == SSH_BIND_OPTIONS_BANNER
            or option == SSH_BIND_OPTIONS_LOG_VERBOSITY_STR):
            rc = lib.ssh_bind_options_set(self.bind, option, cstring(value))
            self.check(rc)
            return rc
        raise RuntimeError("Unhandled option " + str(option))
    def setFd(self, fd):
        lib.ssh_bind_set_fd(self.bind, fd)
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self)
#  SSH_BIND_OPTIONS_BINDPORT,
#  SSH_BIND_OPTIONS_LOG_VERBOSITY,
  

#LIBSSH_API int ssh_bind_set_callbacks(ssh_bind sshbind, ssh_bind_callbacks callbacks,
#    void *userdata);
#    LIBSSH_API void ssh_bind_set_blocking(ssh_bind ssh_bind_o, int blocking);
#LIBSSH_API socket_t ssh_bind_get_fd(ssh_bind ssh_bind_o);
#LIBSSH_API void ssh_bind_set_fd(ssh_bind ssh_bind_o, socket_t fd);
#LIBSSH_API void ssh_bind_fd_toaccept(ssh_bind ssh_bind_o);
