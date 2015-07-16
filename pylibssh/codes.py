#codes, taken straight out of libssh/libssh.h

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