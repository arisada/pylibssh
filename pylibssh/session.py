from . import api
from api import lib
from common import SSHException, cstring
from codes import *

class Session(object):
    """
    SSH Session wrapper.

    :param str hostname: remote ip or host
    :param int port: remote port
    :param str username: remote user name with which you want to authenticate
    """

    session = None

    def __init__(self, hostname=None, port=None, username=None):
        self.session = lib.ssh_new()

        if hostname:
            lib.ssh_options_set(self.session, SSH_OPTIONS_HOST, cstring(hostname))
            
        if username:
            lib.ssh_options_set(self.session, SSH_OPTIONS_USER, cstring(username))

        lib.ssh_options_set(self.session, SSH_OPTIONS_PORT_STR, cstring(port))
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self)
    def connect(self):
        ret = lib.ssh_connect(self.session)
        if ret != SSH_OK and ret != SSH_AGAIN:
            raise SSHException(self)
        return ret
    def getPubkeyHash(self):
        buf = ctypes.POINTER(ctypes.c_ubyte)()
        rc = lib.ssh_get_pubkey_hash(self.session, ctypes.byref(buf))
        self.check(rc)
        #why str ? because "%c"*16 gets converted to unicode
        raw = str(("%c"*16))%tuple(buf[0:16])
        lib.ssh_clean_pubkey_hash(ctypes.byref(buf))
        return raw
    def disconnect(self):
        lib.ssh_disconnect(self.session)
    def setOption(self, option, value):
        if (option == SSH_OPTIONS_PORT_STR or option == SSH_OPTIONS_USER
            or option == SSH_OPTIONS_USER or option == SSH_OPTIONS_SSH_DIR
            or option == SSH_OPTIONS_IDENTITY or option == SSH_OPTIONS_ADD_IDENTITY
            or option == SSH_OPTIONS_KNOWNHOSTS or option == SSH_OPTIONS_LOG_VERBOSITY_STR
            or option == SSH_OPTIONS_CIPHERS_C_S or option == SSH_OPTIONS_CIPHERS_S_C
            or option == SSH_OPTIONS_COMPRESSION_C_S or option == SSH_OPTIONS_COMPRESSION_S_C
            or option == SSH_OPTIONS_PROXYCOMMAND or option == SSH_OPTIONS_BINDADDR
            or option == SSH_OPTIONS_HOST):
            rc = lib.ssh_options_set(self.session, option, cstring(value))
            self.check(rc)
            return rc
        raise RuntimeError("Unhandled option " + str(option))
#missing options
#SSH_OPTIONS_PORT = 1
#SSH_OPTIONS_FD = 3
#SSH_OPTIONS_TIMEOUT = 9
#SSH_OPTIONS_TIMEOUT_USEC = 10
#SSH_OPTIONS_SSH1 = 11
#SSH_OPTIONS_SSH2 = 12
#SSH_OPTIONS_LOG_VERBOSITY = 13
#SSH_OPTIONS_STRICTHOSTKEYCHECK = 21
#SSH_OPTIONS_COMPRESSION = 22
#SSH_OPTIONS_COMPRESSION_LEVEL = 23
#SSH_OPTIONS_KEY_EXCHANGE = 24
#SSH_OPTIONS_HOSTKEYS = 25
    def userauthNone(self):
        rc = lib.ssh_userauth_none(self.session, None)
        self.check(rc)
        return rc
    def userauthList(self):
        rc = lib.ssh_userauth_list(self.session, None)
        self.check(rc)
        return rc
    def userauthPassword(self, password):
        rc = lib.ssh_userauth_password(self.session, None, cstring(password))
        self.check(rc)
        return rc

    def userauthAgent(self):
        rc = lib.ssh_userauth_agent(self.session, None)
        self.check(rc)
        return rc
    def setAgentChannel(self, channel):
        rc = lib.ssh_set_agent_channel(self.session, channel.channel)
        self.check(rc)
        return rc
    def userauthAuto(self, passphrase=None):
        if(passphrase != None):
            passphrase=cstring(passphrase)
        rc = lib.ssh_userauth_publickey_auto(self.session, None, passphrase)
        self.check(rc)
        return rc
    def isServerKnown(self):
        rc = lib.ssh_is_server_known(self.session)
        self.check(rc)
        return rc
    def userauthGssapi(self):
        rc = lib.ssh_userauth_gssapi(self.session)
        self.check(rc)
        return rc
    def setGssapiCreds(self, creds):
        lib.ssh_gssapi_set_creds(self.session, creds)
    def __del__(self):
        if self.session is not None:
            lib.ssh_free(self.session)
    def setCallbacks(self, cb):
        if cb is None:
            lib.ssh_set_callbacks(self.session, None)
            return
        self.callbacks = api.ssh_callbacks_struct()
        self.callbacks.size = ctypes.sizeof(api.ssh_callbacks_struct)
        self.callbacks.userdata = cb
        self.callbacks.auth_function = _auth_cb_object
        self.callbacks.log_function = _log_cb_object
        self.callbacks.connect_status_function = _connect_status_cb_object
        self.callbacks.global_request_function = _global_request_cb_object
        self.callbacks.channel_open_request_x11_function = _channel_open_request_x11_cb_object
        lib.ssh_set_callbacks(self.session, self.callbacks)
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
     
    def blockingflush(self, timeout):
        rc = lib.ssh_blocking_flush(self.session, self.timeout)
        self.check(rc)
        return rc
    def ssh_forward_accept(self, timout_ms):
        rc = lib.ssh_blocking_flush(self.session, self.timeout)
        self.check(rc)
        return rc
    def setBlocking(self, blocking):
        if blocking:
            lib.ssh_set_blocking(self.session, 1)
        else:
            lib.ssh_set_blocking(self.session, 0)
    def isBlocking(self):
        blocking = lib.ssh_is_blocking(self.session)
        if blocking != 0:
            return True
        else:
            return False
    
        

# int ssh_forward_cancel(ssh_session session, const char *address, int port);
# int ssh_forward_listen(ssh_session session, const char *address, int port, int *bound_port);
# const char *ssh_get_disconnect_message(ssh_session session);
# socket_t ssh_get_fd(ssh_session session);
# char *ssh_get_issue_banner(ssh_session session);
# int ssh_get_openssh_version(ssh_session session);
# int ssh_get_publickey(ssh_session session, ssh_key *key);
# int ssh_get_pubkey_hash(ssh_session session, unsigned char **hash);
# int ssh_get_version(ssh_session session);
# int ssh_get_status(ssh_session session);
# int ssh_is_blocking(ssh_session session);
# int ssh_is_connected(ssh_session session);
# int ssh_is_server_known(ssh_session session);
# int ssh_options_copy(ssh_session src, ssh_session *dest);
# int ssh_options_getopt(ssh_session session, int *argcptr, char **argv);
# int ssh_options_parse_config(ssh_session session, const char *filename);
# int ssh_options_get(ssh_session session, enum ssh_options_e type,
#    char **value);
# int ssh_options_get_port(ssh_session session, unsigned int * port_target);
# int ssh_send_ignore (ssh_session session, const char *data);
# int ssh_send_debug (ssh_session session, const char *message, int always_display);
# int ssh_select(ssh_channel *channels, ssh_channel *outchannels, socket_t maxfd,
#    fd_set *readfds, struct timeval *timeout);
# int ssh_service_request(ssh_session session, const char *service);
# int ssh_set_agent_channel(ssh_session session, ssh_channel channel);
# void ssh_set_fd_except(ssh_session session);
# void ssh_set_fd_toread(ssh_session session);
# void ssh_set_fd_towrite(ssh_session session);
# void ssh_silent_disconnect(ssh_session session);
# int ssh_userauth_try_publickey(ssh_session session,
#                                          const char *username,
#                                          const ssh_key pubkey);
# int ssh_userauth_publickey(ssh_session session,
#                                      const char *username,
#                                      const ssh_key privkey);

# int ssh_userauth_kbdint(ssh_session session, const char *user, const char *submethods);
# const char *ssh_userauth_kbdint_getinstruction(ssh_session session);
# const char *ssh_userauth_kbdint_getname(ssh_session session);
# int ssh_userauth_kbdint_getnprompts(ssh_session session);
# const char *ssh_userauth_kbdint_getprompt(ssh_session session, unsigned int i, char *echo);
# int ssh_userauth_kbdint_getnanswers(ssh_session session);
# const char *ssh_userauth_kbdint_getanswer(ssh_session session, unsigned int i);
# int ssh_userauth_kbdint_setanswer(ssh_session session, unsigned int i,
#    const char *answer);
# int ssh_write_knownhost(ssh_session session);
class SessionCallbacks(object):
    """Callback functions to be implemented by the application. These callbacks
    will be called in case of some events"""
    def auth(self, prompt, bufp, echo, verify):
        return 0
    def log(self, priority, message):
        print "log " + message
    def connectStatus(self, status):
        pass
    def globalRequest( self, message):
        return SSH_ERROR
    def channelOpenX11Request(self, originator_address, originator_port):
        return None
