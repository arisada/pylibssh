# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from . import api
from . import sftp
import warnings
import ctypes
import stat
import sys
import os
import io
import select

#****/ERROR RETURN CODES/*****
SSH_OK = 0      
SSH_ERROR = -1  
SSH_AGAIN = -2   
SSH_EOF = -127
#****/SSH_LOG/*****
SSH_LOG_NOLOG = 0
SSH_LOG_WARNING = 1
SSH_LOG_PROTOCOL = 2
SSH_LOG_PACKET = 3
SSH_LOG_FUNCTIONS = 4
SSH_LOG_NONE = 0
SSH_LOG_WARN = 1
SSH_LOG_INFO = 2
SSH_LOG_DEBUG = 3
SSH_LOG_TRACE = 4
#****/SOCKET TYPE/*****
SSH_INVALID_SOCKET = -1
#*****/offsets of methods/*****
SSH_KEX = 0
SSH_HOSTKEYS = 1
SSH_CRYPT_C_S = 2
SSH_CRYPT_S_C = 3
SSH_MAC_C_S = 4
SSH_MAC_S_C = 5
SSH_COMP_C_S = 6
SSH_COMP_S_C = 7
SSH_LANG_C_S = 8
SSH_LANG_S_C = 9
SSH_CRYPT = 2
SSH_MAC = 3
SSH_COMP = 4
SSH_LANG = 5
#*****/SSH_AUTH/******
SSH_AUTH_SUCCESS = 0
SSH_AUTH_DENIED = 1
SSH_AUTH_PARTIAL = 2
SSH_AUTH_INFO = 3
SSH_AUTH_AGAIN = 4
SSH_AUTH_ERROR = -1
#*****/SSH_CHANNEL/******
SSH_CHANNEL_UNKNOWN = 0
SSH_CHANNEL_SESSION = 1
SSH_CHANNEL_DIRECT_TCPIP = 2
SSH_CHANNEL_FORWARDED_TCPIP = 3
SSH_CHANNEL_X11 = 4
#*****/SSH_REQUEST******
SSH_REQUEST_AUTH = 1
SSH_REQUEST_CHANNEL_OPEN = 2
SSH_REQUEST_CHANNEL = 3
SSH_REQUEST_SERVICE = 4
SSH_REQUEST_GLOBAL = 5
#****/AUTH FLAGS/*****
SSH_AUTH_METHOD_UNKNOWN = 0
SSH_AUTH_METHOD_NONE = 0x0001
SSH_AUTH_METHOD_PASSWORD = 0x0002
SSH_AUTH_METHOD_PUBLICKEY = 0x0004
SSH_AUTH_METHOD_HOSTBASED = 0x0008
SSH_AUTH_METHOD_INTERACTIVE = 0x0010
SSH_AUTH_METHOD_GSSAPI_MIC = 0x0020
SSH_CHANNEL_REQUEST_UNKNOWN = 0
SSH_CHANNEL_REQUEST_PTY = 1
SSH_CHANNEL_REQUEST_EXEC = 2
SSH_CHANNEL_REQUEST_SHELL = 3
SSH_CHANNEL_REQUEST_ENV = 4
SSH_CHANNEL_REQUEST_SUBSYSTEM = 5
SSH_CHANNEL_REQUEST_WINDOW_CHANGE = 6
SSH_CHANNEL_REQUEST_X11 = 7
SSH_GLOBAL_REQUEST_UNKNOWN = 0
SSH_GLOBAL_REQUEST_TCPIP_FORWARD = 1
SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD = 2
SSH_PUBLICKEY_STATE_ERROR = -1
SSH_PUBLICKEY_STATE_NONE = 0
SSH_PUBLICKEY_STATE_VALID = 1
SSH_PUBLICKEY_STATE_WRONG = 2
SSH_SERVER_ERROR = -1,
SSH_SERVER_NOT_KNOWN = 0
SSH_SERVER_KNOWN_OK = 1
SSH_SERVER_KNOWN_CHANGED = 2
SSH_SERVER_FOUND_OTHER = 3
SSH_SERVER_FILE_NOT_FOUND = 4
MD5_DIGEST_LEN = 16
#****/ERROR/*****
SSH_NO_ERROR = 0
SSH_REQUEST_DENIED = 1
SSH_FATAL = 2
SSH_EINTR = 3
#****/TYPES FOR KEYS/****
SSH_KEYTYPE_UNKNOWN = 0 
SSH_KEYTYPE_DSS = 1 
SSH_KEYTYPE_RSA = 2
SSH_KEYTYPE_RSA1 = 3
SSH_KEYTYPE_ECDSA = 4
SSH_KEY_CMP_PUBLIC = 0 
SSH_KEY_CMP_PRIVATE = 1
#****/SSH_OPTIONS/****
SSH_OPTIONS_HOST = 0
SSH_OPTIONS_PORT = 1
SSH_OPTIONS_PORT_STR = 2
SSH_OPTIONS_FD = 3
SSH_OPTIONS_USER = 4
SSH_OPTIONS_SSH_DIR = 5
SSH_OPTIONS_IDENTITY = 6
SSH_OPTIONS_ADD_IDENTITY = 7
SSH_OPTIONS_KNOWNHOSTS = 8
SSH_OPTIONS_TIMEOUT = 9
SSH_OPTIONS_TIMEOUT_USEC = 10
SSH_OPTIONS_SSH1 = 11
SSH_OPTIONS_SSH2 = 12
SSH_OPTIONS_LOG_VERBOSITY = 13
SSH_OPTIONS_LOG_VERBOSITY_STR = 14
SSH_OPTIONS_CIPHERS_C_S = 15
SSH_OPTIONS_CIPHERS_S_C = 16
SSH_OPTIONS_COMPRESSION_C_S = 17
SSH_OPTIONS_COMPRESSION_S_C = 18
SSH_OPTIONS_PROXYCOMMAND = 19
SSH_OPTIONS_BINDADDR = 20
SSH_OPTIONS_STRICTHOSTKEYCHECK = 21
SSH_OPTIONS_COMPRESSION = 22
SSH_OPTIONS_COMPRESSION_LEVEL = 23
SSH_OPTIONS_KEY_EXCHANGE = 24
SSH_OPTIONS_HOSTKEYS = 25

SSH_BIND_OPTIONS_BINDADDR = 0
SSH_BIND_OPTIONS_BINDPORT = 1
SSH_BIND_OPTIONS_BINDPORT_STR = 2
SSH_BIND_OPTIONS_HOSTKEY = 3
SSH_BIND_OPTIONS_DSAKEY = 4
SSH_BIND_OPTIONS_RSAKEY = 5
SSH_BIND_OPTIONS_BANNER = 6
SSH_BIND_OPTIONS_LOG_VERBOSITY = 7
SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
#****/SSH_SCP_REQUEST/****
SSH_SCP_REQUEST_NEWDIR = 1
SSH_SCP_REQUEST_NEWFILE = 2
SSH_SCP_REQUEST_EOF = 3
SSH_SCP_REQUEST_ENDDIR = 4
SSH_SCP_REQUEST_WARNING = 5
#****/CALLBACKS/****
SSH_SOCKET_FLOW_WRITEWILLBLOCK = 1
SSH_SOCKET_FLOW_WRITEWONTBLOCK = 2
SSH_SOCKET_EXCEPTION_EOF = 1
SSH_SOCKET_EXCEPTION_ERROR = 2
SSH_SOCKET_CONNECTED_OK  = 1
SSH_SOCKET_CONNECTED_ERROR  = 2
SSH_SOCKET_CONNECTED_TIMEOUT = 3
# Python 2.7 compatibility layer

if sys.version_info[0] < 3:
    def bytes(data, encoding="utf-8"):
        return data.encode(encoding)

    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes
    
def _cstring(string):
    if isinstance(string, text_type):
        return bytes(string, "utf-8")
    return string

_ssh = api.lib

class SSHException(Exception):
    def __init__(self, session):
        if(isinstance(session, Session)):
            self.msg = _ssh.ssh_get_error(session.session).decode('utf-8')
        else:
            self.msg = _ssh.ssh_get_error(session.bind).decode('utf-8')
    def __str__(self):
        return "SSH error: "+self.msg
    
class Channel(object):
    channel = None
    cb_ref = None
    def __init__(self, session):
        self.session = session
        self.channel = _ssh.ssh_channel_new(session.session)
        if (self.channel == None):
            raise SSHException(self.session)
    def close(self):
        rc = _ssh.ssh_channel_close(self.channel)
        self.check(rc)
        return rc
    def isClosed(self):
        rc = _ssh.ssh_channel_is_closed(self.channel)
        return rc != 0
    def isOpen(self):
        rc = _ssh.ssh_channel_is_open(self.channel)
        return rc != 0
    def isEof(self):
        rc = _ssh.ssh_channel_is_eof(self.channel)
        return rc != 0
    def poll(self, stderr=False, timeout=None):
        if (timeout != None):
            rc = _ssh.ssh_channel_poll_timeout(self.channel, timeout, int(stderr))
        else:
            rc = _ssh.ssh_channel_poll(self.channel, int(stderr))
        self.check(rc)
        return rc
    def openSession(self):
        rc = _ssh.ssh_channel_open_session(self.channel)
        self.check(rc)
        return rc
    def openX11(self, originator_address, originator_port):
        rc = _ssh.ssh_channel_open_x11(self.channel, str(originator_address), int(originator_port))
        self.check(rc)
        return rc
    def openAuthAgent(self):
        rc = _ssh.ssh_channel_open_auth_agent(self.channel)
        self.check(rc)
        return rc
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self.session)
    def getExitStatus(self):
        rc = _ssh.ssh_channel_get_exit_status(self.channel)
        return rc
    def getSession(self):
        return self.session
    def changePtySize(self, cols, rows):
        rc = _ssh.ssh_channel_change_pty_size(self.channel, cols, rows)
        self.check(rc)
        return rc
    def requestX11(self, single_connection, protocol, cookie, screen_number):
        rc = _ssh.ssh_channel_request_x11(self.channel, single_connection, protocol, cookie, screen_number)
        self.check(rc)
        return rc
# ssh_channel ssh_channel_accept_x11(ssh_channel channel, int timeout_ms);
# int ssh_channel_change_pty_size(ssh_channel channel,int cols,int rows);
# int ssh_channel_open_forward(ssh_channel channel, const char *remotehost,
#    int remoteport, const char *sourcehost, int localport);
# int ssh_channel_request_env(ssh_channel channel, const char *name, const char *value);
# int ssh_channel_request_send_signal(ssh_channel channel, const char *signum);
# int ssh_channel_request_sftp(ssh_channel channel);
# int ssh_channel_request_subsystem(ssh_channel channel, const char *subsystem);
# int ssh_channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
#    const char *cookie, int screen_number);
# int ssh_channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct
#        timeval * timeout);
# void ssh_channel_set_blocking(ssh_channel channel, int blocking);
# uint32_t ssh_channel_window_size(ssh_channel channel);
    def requestShell(self):
        rc = _ssh.ssh_channel_request_shell(self.channel)
        self.check(rc)
        return rc
    
    def requestExec(self, cmd):
        rc = _ssh.ssh_channel_request_exec(self.channel, _cstring(cmd))
        self.check(rc)
        return rc
    
    def requestPty(self, term="vt220", cols = 80, rows= 25):
        rc = _ssh.ssh_channel_request_pty_size(self.channel, _cstring(term), cols, rows)
        self.check(rc)
        return rc
    
    def requestSubsystem(self, subsystem):
        rc = _ssh.ssh_channel_request_subsystem(self.channel, _cstring(subsystem))
        self.check(rc)
        return rc
    
    def sendEof(self):
        rc = _ssh.ssh_channel_send_eof(self.channel)
        self.check(rc)
        return rc
    
    def write(self, data, stderr=False):
        data = _cstring(data)
        if(stderr):
            written = _ssh.ssh_channel_write_stderr(self.channel, data, len(data))
        else:
            written = _ssh.ssh_channel_write(self.channel, data, len(data))
        self.check(written)
        return written

    def read(self, num, stderr=False):
        #nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        buf = ctypes.create_string_buffer(num)
        rc = _ssh.ssh_channel_read(self.channel, buf, num, int(stderr))
        self.check(rc)
        if(rc >= 0):
            return buf.raw[:rc]
        else:
            return rc
    def readNonblocking(self, num, stderr=False):
        buf = ctypes.create_string_buffer(num)
        rc = _ssh.ssh_channel_read_nonblocking(self.channel, buf, num, int(stderr))
        self.check(rc)
        if(rc >= 0):
            return buf.raw[:rc]
        else:
            return rc        
    def __del__(self):
        if self.channel is not None:
            _ssh.ssh_channel_free(self.channel)

    def setCallbacks(self, cb):
        if cb is None:
            _ssh.ssh_set_channel_callbacks(self.channel, None)
            return
        self.callbacks = api.ssh_channel_callbacks_struct()
        self.callbacks.size = ctypes.sizeof(api.ssh_channel_callbacks_struct)
        self.callbacks.userdata = cb
        self.callbacks.channel_data_function = _channel_data_cb_object
        self.callbacks.channel_eof_function = _channel_eof_cb_object
        self.callbacks.channel_close_function = _channel_close_cb_object
        self.callbacks.channel_signal_function = _channel_signal_cb_object
        self.callbacks.channel_exit_status_function = _channel_exit_status_cb_object
        self.callbacks.channel_exit_signal_function = _channel_exit_signal_cb_object
        self.callbacks.channel_pty_request_function = _channel_pty_request_cb_object
        self.callbacks.channel_shell_request_function = _channel_shell_request_cb_object
        self.callbacks.channel_auth_agent_req_function = _channel_auth_agent_req_cb_object
        self.callbacks.channel_x11_req_function = _channel_x11_req_cb_object
        self.callbacks.channel_pty_window_change_function = _channel_pty_window_change_cb_object
        self.callbacks.channel_exec_request_function = _channel_exec_request_cb_object
        self.callbacks.channel_env_request_function = _channel_env_request_cb_object
        self.callbacks.channel_subsystem_request_function = _channel_subsystem_request_cb_object
        _ssh.ssh_set_channel_callbacks(self.channel, self.callbacks)
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
    def getCallbacks(self):
        return self.cb_ref

class Session(object):
    """
    SSH Session wrapper.

    :param str hostname: remote ip or host
    :param int port: remote port
    :param str username: remote user name with which you want to authenticate
    """

    session = None

    def __init__(self, hostname=None, port=None, username=None):
        self.session = _ssh.ssh_new()

        if hostname:
            _ssh.ssh_options_set(self.session, SSH_OPTIONS_HOST, _cstring(hostname))
            
        if username:
            _ssh.ssh_options_set(self.session, SSH_OPTIONS_USER, _cstring(username))

        _ssh.ssh_options_set(self.session, SSH_OPTIONS_PORT_STR, _cstring(port))
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self)
    def connect(self):
        ret = _ssh.ssh_connect(self.session)
        if ret != SSH_OK and ret != SSH_AGAIN:
            raise SSHException(self)
        return ret
    def getPubkeyHash(self):
        buf = ctypes.POINTER(ctypes.c_ubyte)()
        rc = _ssh.ssh_get_pubkey_hash(self.session, ctypes.byref(buf))
        self.check(rc)
        #why str ? because "%c"*16 gets converted to unicode
        raw = str(("%c"*16))%tuple(buf[0:16])
        _ssh.ssh_clean_pubkey_hash(ctypes.byref(buf))
        return raw
    def disconnect(self):
        _ssh.ssh_disconnect(self.session)
    def setOption(self, option, value):
        if (option == SSH_OPTIONS_PORT_STR or option == SSH_OPTIONS_USER
            or option == SSH_OPTIONS_USER or option == SSH_OPTIONS_SSH_DIR
            or option == SSH_OPTIONS_IDENTITY or option == SSH_OPTIONS_ADD_IDENTITY
            or option == SSH_OPTIONS_KNOWNHOSTS or option == SSH_OPTIONS_LOG_VERBOSITY_STR
            or option == SSH_OPTIONS_CIPHERS_C_S or option == SSH_OPTIONS_CIPHERS_S_C
            or option == SSH_OPTIONS_COMPRESSION_C_S or option == SSH_OPTIONS_COMPRESSION_S_C
            or option == SSH_OPTIONS_PROXYCOMMAND or option == SSH_OPTIONS_BINDADDR
            or option == SSH_OPTIONS_HOST):
            rc = _ssh.ssh_options_set(self.session, option, _cstring(value))
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
        rc = _ssh.ssh_userauth_none(self.session, None)
        self.check(rc)
        return rc
    def userauthList(self):
        rc = _ssh.ssh_userauth_list(self.session, None)
        self.check(rc)
        return rc
    def userauthPassword(self, password):
        rc = _ssh.ssh_userauth_password(self.session, None, _cstring(password))
        self.check(rc)
        return rc

    def userauthAgent(self):
        rc = _ssh.ssh_userauth_agent(self.session, None)
        self.check(rc)
        return rc
    def setAgentChannel(self, channel):
        rc = _ssh.ssh_set_agent_channel(self.session, channel.channel)
        self.check(rc)
        return rc
    def userauthAuto(self, passphrase=None):
        if(passphrase != None):
            passphrase=_cstring(passphrase)
        rc = _ssh.ssh_userauth_publickey_auto(self.session, None, passphrase)
        self.check(rc)
        return rc
    def isServerKnown(self):
        rc = _ssh.ssh_is_server_known(self.session)
        self.check(rc)
        return rc
    def userauthGssapi(self):
        rc = _ssh.ssh_userauth_gssapi(self.session)
        self.check(rc)
        return rc
    def setGssapiCreds(self, creds):
        _ssh.ssh_gssapi_set_creds(self.session, creds)
    def __del__(self):
        if self.session is not None:
            _ssh.ssh_free(self.session)
    def setCallbacks(self, cb):
        if cb is None:
            _ssh.ssh_set_callbacks(self.session, None)
            return
        self.callbacks = api.ssh_callbacks_struct()
        self.callbacks.size = ctypes.sizeof(api.ssh_callbacks_struct)
        self.callbacks.userdata = cb
        self.callbacks.auth_function = _auth_cb_object
        self.callbacks.log_function = _log_cb_object
        self.callbacks.connect_status_function = _connect_status_cb_object
        self.callbacks.global_request_function = _global_request_cb_object
        self.callbacks.channel_open_request_x11_function = _channel_open_request_x11_cb_object
        _ssh.ssh_set_callbacks(self.session, self.callbacks)  
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
     
    def blockingflush(self, timeout):
        rc = _ssh.ssh_blocking_flush(self.session, self.timeout)
        self.check(rc)
        return rc
    def ssh_forward_accept(self, timout_ms):
        rc = _ssh.ssh_blocking_flush(self.session, self.timeout)
        self.check(rc)
        return rc
    def setBlocking(self, blocking):
        if blocking:
            _ssh.ssh_set_blocking(self.session, 1)
        else:
            _ssh.ssh_set_blocking(self.session, 0)
    def isBlocking(self):
        blocking = _ssh.ssh_is_blocking(self.session)
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
        rc = _ssh.ssh_handle_key_exchange(self.session)
        self.check(rc)
        return rc
    def setAuthMethods(self, authmethods):
        _ssh.ssh_set_auth_methods(self.session, authmethods)
    def setCallbacks(self, cb):
        self.servercallbacks = api.ssh_server_callbacks_struct()
        self.servercallbacks.auth_none_function = _auth_none_cb_object
        self.servercallbacks.auth_password_function = _auth_password_cb_object
        self.servercallbacks.auth_gssapi_mic_function = _auth_gssapi_mic_cb_object
        self.servercallbacks.auth_pubkey_function = _auth_pubkey_cb_object
        self.servercallbacks.channel_open_request_session_function = _channel_open_request_session_cb_object
        self.servercallbacks.size = ctypes.sizeof(api.ssh_server_callbacks_struct)
        self.servercallbacks.userdata = cb
        _ssh.ssh_set_server_callbacks(self.session, self.servercallbacks)
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
        super(ServerSession, self).setCallbacks(cb)
    def getGssapiCreds(self):
        return _ssh.ssh_gssapi_get_creds(self.session)
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
 
def _channel_data_function(sessionp, channelp, datap, length, is_stderrp, userargp):
    string = ctypes.string_at(datap, length)
    return userargp.data(string, is_stderrp)
def _channel_eof_function(sessionp, channelp, userargp):
    userargp.eof()
def _channel_close_function(sessionp, channelp, userargp):
    userargp.close()
def _channel_signal_function(sessionp, channelp, signalp, userargp):
    userargp.signal(signalp)

def _channel_exit_signal_function(sessionp, channelp, siganlp, corep, errmsgp, langp, userargp):
    userargp.exitSignal(errmsgp)
def _channel_exit_status_function(sessionp, channelp, status, userargp):
    userargp.exitStatus(status)
def _channel_pty_request_function(sessionp, channelp, term, width, height, pxwidth, pxheight, userargp):
    return userargp.requestPty(term, width, height, pxwidth, pxheight)
def _channel_shell_request_function(sessionp, channelp, userargp):
    return userargp.requestShell()  
def _channel_auth_agent_req_function(sessionp, channelp, userargp):
    return userargp.requestAuthAgent()
def _channel_x11_req_function(sessionp, channelp, single_connection, auth_protocol, auth_cookie,\
                             screen_number, userargp):
    return userargp.requestX11(single_connection, auth_protocol, auth_cookie, screen_number)
def _channel_pty_window_change_function(sessionp, channelp, width, height, pxwidth, pxheight, userargp):
    return userargp.ptyWindowChange(width, height, pxwidth, pxheight)
def _channel_exec_request_function(sessionp, channelp, command, userargp):
    return userargp.requestExec(command)
def _channel_env_request_function(sessionp, channelp, env_name, env_value, userargp):
    return userargp.requestEnv(env_name, env_value)
def _channel_subsystem_request_function(sessionp, channelp, subsystem, userargp):
    return userargp.requestSubsystem(subsystem)

_channel_data_cb_object = api.channel_data_cb(_channel_data_function)
_channel_eof_cb_object = api.channel_eof_cb(_channel_eof_function)
_channel_close_cb_object = api.channel_close_cb(_channel_close_function)
_channel_signal_cb_object = api.channel_signal_cb(_channel_signal_function)
_channel_exit_status_cb_object = api.channel_exit_status_cb(_channel_exit_status_function)
_channel_exit_signal_cb_object = api.channel_exit_signal_cb(_channel_exit_signal_function)
_channel_pty_request_cb_object = api.channel_pty_request_cb(_channel_pty_request_function)
_channel_shell_request_cb_object = api.channel_shell_request_cb(_channel_shell_request_function)
_channel_auth_agent_req_cb_object = api.channel_auth_agent_req_cb(_channel_auth_agent_req_function)
_channel_x11_req_cb_object = api.channel_x11_req_cb(_channel_x11_req_function)
_channel_pty_window_change_cb_object = api.channel_pty_window_change_cb(_channel_pty_window_change_function)
_channel_exec_request_cb_object = api.channel_exec_request_cb(_channel_exec_request_function)
_channel_env_request_cb_object = api.channel_env_request_cb(_channel_env_request_function)
_channel_subsystem_request_cb_object = api.channel_subsystem_request_cb(_channel_subsystem_request_function)

class ChannelCallbacks(object):
    def __init__ (self, channel):
        self.channel = channel
    def data(self, data, stderr):
        return 0
    def eof(self):
        print "channel"  
    def close(self):
        print "close channel"
    def signal(self, signal):
        print " signal"
    def exitStatus(self, status):
        pass
    def requestPty(self, term, width, height, pxwidth, pxheight):
        return SSH_ERROR
    def requestShell(self):
        return SSH_ERROR
    def requestAuthAgent(self):
        return SSH_OK
    def requestX11(self, single_connection, auth_protocol, auth_cookie,\
                screen_number):
        return SSH_ERROR
    def ptyWindowChange(self, width, height, pxwidth, pxheight):
        return SSH_OK
    def requestExec(self, command):
        return SSH_ERROR
    def requestEnv(self, env_name, env_value):
        return SSH_ERROR
    def requestSubsystem(self, subsystem):
        return SSH_ERROR
#*******************************************************
class Bind(object):
    bind = None
    def __init__(self):
        self.bind = _ssh.ssh_bind_new()
    def listen(self):
        rc = _ssh.ssh_bind_listen(self.bind)
        self.check(rc)
        return rc
    def __del__(self):
        if(self.bind is not None):
            _ssh.ssh_bind_free(self.bind)
            self.bind=None
    def accept(self, session, fd = None):
        if (fd != None):
            rc = _ssh.ssh_bind_accept_fd(self.bind, session.session, fd)
        else:
            rc = _ssh.ssh_bind_accept(self.bind, session.session)
        self.check(rc)
        return rc
    def setOption(self, option, value):
        if (option == SSH_BIND_OPTIONS_BINDADDR or option == SSH_BIND_OPTIONS_BINDPORT_STR
            or option == SSH_BIND_OPTIONS_HOSTKEY or option == SSH_BIND_OPTIONS_DSAKEY
            or option == SSH_BIND_OPTIONS_RSAKEY or option == SSH_BIND_OPTIONS_BANNER
            or option == SSH_BIND_OPTIONS_LOG_VERBOSITY_STR):
            rc = _ssh.ssh_bind_options_set(self.bind, option, _cstring(value))
            self.check(rc)
            return rc
        raise RuntimeError("Unhandled option " + str(option))
    def setFd(self, fd):
        _ssh.ssh_bind_set_fd(self.bind, fd)
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

class EventFdCallbacks(object):
    fd = None
    def __init__ (self, fd):
        self.fd = fd
    def pollEvent(self, fd, revent):
        if(self.fd.fileno() != fd):
            raise RuntimeException("Different fd in callbacks")
        if (revent & select.POLLIN):
            self.pollInEvent()
        if (revent & select.POLLERR):
            self.pollErrEvent()
        if (revent & select.POLLOUT):
            self.pollOutEvent()
        return 0
    def pollInEvent(self):
        pass
    def pollOutEvent(self):
        pass
    def pollErrEvent(self):
        pass

def _event_function(fd, revent, userargp):
    return userargp.pollEvent(fd, revent)

_event_cb_object = api.event_cb(_event_function)


class Event(object):
    event = None
    def __init__(self):
        self.event = _ssh.ssh_event_new()
    def __del__(self):
        if (self.event is not None):
            _ssh.ssh_event_free(self.event)
            self.event=None
    def addSession(self, session):
        _ssh.ssh_event_add_session(self.event, session.session)
    def removeSession(self, session):
        _ssh.ssh_event_remove_session(self.event, session.session)
    def doPoll(self, timeout=-1):
        rc = _ssh.ssh_event_dopoll(self.event, timeout)
        if (rc == SSH_ERROR):
            raise RuntimeError("event_dopoll failed")
        return rc
    def addFd(self, fdcallback, events):
        _ssh.ssh_event_add_fd(self.event, fdcallback.fd.fileno(), events, _event_cb_object, fdcallback)
    def removeFd(self, fd):
        _ssh.ssh_event_remove_fd(self.event, fd)

class Sftp(object):
    sftp = None
    INIT = 1
    VERSION = 2
    OPEN = 3
    CLOSE = 4
    READ = 5
    WRITE = 6
    LSTAT = 7
    FSTAT = 8
    SETSTAT = 9
    FSETSTAT = 10
    OPENDIR = 11
    READDIR = 12
    REMOVE = 13
    MKDIR = 14
    RMDIR = 15
    REALPATH = 16
    STAT = 17
    RENAME = 18
    READLINK = 19
    SYMLINK = 20

    FLAG_READ = 0x01
    FLAG_WRITE = 0x02
    FLAG_APPEND = 0x04
    FLAG_CREAT = 0x08
    FLAG_TRUNC = 0x10
    FLAG_EXCL = 0x20
    FLAG_TEXT = 0x40    
    def __init__(self, session, channel=None):
        if channel is not None:
            self.sftp = _ssh.sftp_new_channel(session.session, channel.channel)
        else:
            self.sftp = _ssh.sftp_new(session.session)
    def init(self):
        rc = _ssh.sftp_init(self.sftp)
        self.check(rc)
        return rc
    def __del__(self):
        _ssh.sftp_free(self.sftp)
        self.sftp = None
    def sendClientMessage(self, msg):
        rc = _ssh.sftp_send_client_message(self.sftp, msg.msg)
        self.check(rc)
        return rc
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self)    
    
class SftpServer(object):
    sftp = None
    def __init__(self, channel):
        _channel = channel.channel
        _session = channel.getSession().session
        self.sftp = _ssh.sftp_server_new(_session, _channel)
    def init (self):
        rc = _ssh.sftp_server_init(self.sftp)
        self.check(rc)
        return rc
    
    def getClientMessage(self):
        _msg = _ssh.sftp_get_client_message(self.sftp)
        if _msg is not None:
            return SftpClientMessage(_msg)
        else:
            return None
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self)    
        
class SftpClientMessage(object):
    msg = None
    data = None
    def __init__(self, msg):
        self.msg = msg
    def __del__(self):
        _ssh.sftp_client_message_free(self.msg)
        self.msg = None
        self.data = None
    def getType(self):
        return _ssh.sftp_client_message_get_type(self.msg)

    def getFilename(self):
        return _ssh.sftp_client_message_get_filename(self.msg)
    def setFilename(self, name):
        _ssh.sftp_client_message_set_filename(self.msg, name)
        
    def getData(self):
        if self.data is None:
            self.data = _ssh.sftp_client_message_get_data(self.msg)
        return self.data
    def getFlags(self):
        return _ssh.sftp_client_message_get_flags(self.msg)
    
class Key(object):
    _key = None
    _immutable = False
    def __init__(self, sshkeyp=None):
        if sshkeyp is not None:
            self._key = sshkeyp
            self._immutable = True
        else:
            self._key = _ssh.ssh_key_new()
    def __del__(self):
        if self._key is not None and not self._immutable:
            _ssh.ssh_key_free(self._key)
        self._key = None
        self._immutable = False
    def exportBase64(self):
        b64 = ctypes.c_char_p()
        ret = _ssh.ssh_pki_export_pubkey_base64(self._key, b64)
        #print "b64 : " + str(b64.value)
        return str(b64.value)