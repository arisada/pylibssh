from . import api
from api import lib

class Channel(object):
    channel = None
    cb_ref = None
    def __init__(self, session):
        self.session = session
        self.channel = lib.ssh_channel_new(session.session)
        if (self.channel == None):
            raise SSHException(self.session)
    def close(self):
        rc = lib.ssh_channel_close(self.channel)
        self.check(rc)
        return rc
    def isClosed(self):
        rc = lib.ssh_channel_is_closed(self.channel)
        return rc != 0
    def isOpen(self):
        rc = lib.ssh_channel_is_open(self.channel)
        return rc != 0
    def isEof(self):
        rc = lib.ssh_channel_is_eof(self.channel)
        return rc != 0
    def poll(self, stderr=False, timeout=None):
        if (timeout != None):
            rc = lib.ssh_channel_poll_timeout(self.channel, timeout, int(stderr))
        else:
            rc = lib.ssh_channel_poll(self.channel, int(stderr))
        self.check(rc)
        return rc
    def openSession(self):
        rc = lib.ssh_channel_open_session(self.channel)
        self.check(rc)
        return rc
    def openX11(self, originator_address, originator_port):
        rc = lib.ssh_channel_open_x11(self.channel, str(originator_address), int(originator_port))
        self.check(rc)
        return rc
    def openAuthAgent(self):
        rc = lib.ssh_channel_open_auth_agent(self.channel)
        self.check(rc)
        return rc
    def check(self, rc):
        if (rc == SSH_ERROR):
            raise SSHException(self.session)
    def getExitStatus(self):
        rc = lib.ssh_channel_get_exit_status(self.channel)
        return rc
    def getSession(self):
        return self.session
    def changePtySize(self, cols, rows):
        rc = lib.ssh_channel_change_pty_size(self.channel, cols, rows)
        self.check(rc)
        return rc
    def requestX11(self, single_connection, protocol, cookie, screen_number):
        rc = lib.ssh_channel_request_x11(self.channel, single_connection, protocol, cookie, screen_number)
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
        rc = lib.ssh_channel_request_shell(self.channel)
        self.check(rc)
        return rc
    
    def requestExec(self, cmd):
        rc = lib.ssh_channel_request_exec(self.channel, _cstring(cmd))
        self.check(rc)
        return rc
    
    def requestPty(self, term="vt220", cols = 80, rows= 25):
        rc = lib.ssh_channel_request_pty_size(self.channel, _cstring(term), cols, rows)
        self.check(rc)
        return rc
    
    def requestSubsystem(self, subsystem):
        rc = lib.ssh_channel_request_subsystem(self.channel, _cstring(subsystem))
        self.check(rc)
        return rc
    
    def sendEof(self):
        rc = lib.ssh_channel_send_eof(self.channel)
        self.check(rc)
        return rc
    
    def write(self, data, stderr=False):
        data = _cstring(data)
        if(stderr):
            written = lib.ssh_channel_write_stderr(self.channel, data, len(data))
        else:
            written = lib.ssh_channel_write(self.channel, data, len(data))
        self.check(written)
        return written

    def read(self, num, stderr=False):
        #nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        buf = ctypes.create_string_buffer(num)
        rc = lib.ssh_channel_read(self.channel, buf, num, int(stderr))
        self.check(rc)
        if(rc >= 0):
            return buf.raw[:rc]
        else:
            return rc
    def readNonblocking(self, num, stderr=False):
        buf = ctypes.create_string_buffer(num)
        rc = lib.ssh_channel_read_nonblocking(self.channel, buf, num, int(stderr))
        self.check(rc)
        if(rc >= 0):
            return buf.raw[:rc]
        else:
            return rc
    def __del__(self):
        if self.channel is not None:
            lib.ssh_channel_free(self.channel)

    def setCallbacks(self, cb):
        if cb is None:
            lib.ssh_set_channel_callbacks(self.channel, None)
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
        lib.ssh_set_channel_callbacks(self.channel, self.callbacks)
        #keep a reference to cb so the GC won't delete it
        self.cb_ref = cb
    def getCallbacks(self):
        return self.cb_ref

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
