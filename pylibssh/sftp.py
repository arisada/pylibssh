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
