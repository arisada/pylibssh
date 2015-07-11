import sys
from api import lib
# Python 2.7 compatibility layer

if sys.version_info[0] < 3:
    def bytes(data, encoding="utf-8"):
        return data.encode(encoding)

    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


def cstring(string):
    if isinstance(string, text_type):
        return bytes(string, "utf-8")
    return string

# avoid cross-dependence
class Session(object):
    pass

class SSHException(Exception):
    def __init__(self, session):
        if(isinstance(session, Session)):
            self.msg = lib.ssh_get_error(session.session).decode('utf-8')
        else:
            self.msg = lib.ssh_get_error(session.bind).decode('utf-8')
    def __str__(self):
        return "SSH error: "+self.msg
    
class Key(object):
    _key = None
    _immutable = False
    def __init__(self, sshkeyp=None):
        if sshkeyp is not None:
            self._key = sshkeyp
            self._immutable = True
        else:
            self._key = lib.ssh_key_new()
    def __del__(self):
        if self._key is not None and not self._immutable:
            lib.ssh_key_free(self._key)
        self._key = None
        self._immutable = False
    def exportBase64(self):
        b64 = ctypes.c_char_p()
        ret = lib.ssh_pki_export_pubkey_base64(self._key, b64)
        #print "b64 : " + str(b64.value)
        return str(b64.value)