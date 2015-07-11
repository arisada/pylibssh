# -*- coding: utf-8 -*-

import ctypes
import ctypes.util

def load_library():
    libpath = ctypes.util.find_library('ssh')
    libssh = ctypes.CDLL(libpath)
    return libssh

class ssh_bind_callbacks_struct(ctypes.Structure):
    pass
ssh_bind_callbacks_struct._fields_ = [
        ('size', ctypes.c_ulong),
        ('incoming_connection', ctypes.c_void_p)]


log_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p,
          ctypes.py_object)
global_request_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)
auth_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
           ctypes.c_long, ctypes.c_int, ctypes.c_int, ctypes.py_object)
connect_status_cb = ctypes.CFUNCTYPE(None, ctypes.py_object, ctypes.c_float)
channel_open_request_x11_cb = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_char_p, ctypes.c_int, ctypes.py_object)
class ssh_callbacks_struct(ctypes.Structure):
    pass
ssh_callbacks_struct._fields_ = [
        ('size', ctypes.c_ulong),
        ('userdata', ctypes.py_object),
        ('auth_function', auth_cb),
        ('log_function', log_cb),
        ('connect_status_function', connect_status_cb), 
        ('global_request_function', global_request_cb),
        ('channel_open_request_x11_function', channel_open_request_x11_cb)]

# Define prototypes of callbacks.
#fonction_cb = CFUNCTYPE(ctypes.c_int    ## valeur de retour
#                , POINTER(c_int), POINTER(c_int) ## arguments
#                )
auth_password_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.py_object)
auth_none_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, 
                    ctypes.c_char_p, ctypes.py_object)
auth_pubkey_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                    ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.py_object)

auth_gssapi_mic_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, 
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.py_object)
channel_open_request_session_cb = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)
class ssh_server_callbacks_struct(ctypes.Structure):
    pass
ssh_server_callbacks_struct._fields_ = [
        ('size', ctypes.c_ulong),
        ('userdata',  ctypes.py_object),
        ('auth_password_function', auth_password_cb),
        ('auth_none_function', auth_none_cb),
        ('auth_gssapi_mic_function', auth_gssapi_mic_cb),
        ('auth_pubkey_function', auth_pubkey_cb),
        ('service_request_function', ctypes.c_void_p),
        ('channel_open_request_session_function', channel_open_request_session_cb)]

channel_data_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_uint, ctypes.c_int, ctypes.py_object)
channel_eof_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)
channel_close_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)
channel_signal_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.py_object)
channel_exit_status_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.py_object)
channel_exit_signal_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                          ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.py_object)
channel_pty_request_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                          ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.py_object)

channel_shell_request_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)

channel_auth_agent_req_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.py_object)

channel_x11_req_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, \
                                      ctypes.c_char_p, ctypes.c_uint, ctypes.py_object)

channel_pty_window_change_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, \
                                                ctypes.c_int,ctypes.c_int,ctypes.c_int, ctypes.py_object)

channel_exec_request_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, \
                                           ctypes.py_object)

channel_env_request_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, \
                                          ctypes.c_char_p, ctypes.py_object)

channel_subsystem_request_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, \
                                           ctypes.py_object)

class ssh_channel_callbacks_struct(ctypes.Structure):
    pass
ssh_channel_callbacks_struct._fields_ = [
        ('size', ctypes.c_ulong),
        ('userdata',  ctypes.py_object),
        ('channel_data_function', channel_data_cb),
        ('channel_eof_function', channel_eof_cb),
        ('channel_close_function', channel_close_cb),
        ('channel_signal_function', channel_signal_cb),
        ('channel_exit_status_function', channel_exit_status_cb),
        ('channel_exit_signal_function', channel_exit_signal_cb),
        ('channel_pty_request_function', channel_pty_request_cb),
        ('channel_shell_request_function', channel_shell_request_cb),
        ('channel_auth_agent_req_function', channel_auth_agent_req_cb),
        ('channel_x11_req_function', channel_x11_req_cb),
        ('channel_pty_window_change_function', channel_pty_window_change_cb),
        ('channel_exec_request_function', channel_exec_request_cb),
        ('channel_env_request_function', channel_env_request_cb),
        ('channel_subsystem_request_function', channel_subsystem_request_cb)]

#the event_callback used with poll events
event_cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.py_object)

try:
    lib = load_library()
    
    lib.ssh_blocking_flush.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_blocking_flush.restype = ctypes.c_int
    
    lib.ssh_channel_accept_x11.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_channel_accept_x11.restype = ctypes.c_void_p
    
    lib.ssh_channel_change_pty_size.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.ssh_channel_change_pty_size.restype = ctypes.c_int

    lib.ssh_channel_close.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_close.restype = ctypes.c_int
    
    lib.ssh_channel_free.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_free.restype  = None

    lib.ssh_channel_get_exit_status.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_get_exit_status.restype = ctypes.c_int

    lib.ssh_channel_get_session.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_get_session.restype = ctypes.c_void_p

    lib.ssh_channel_is_closed.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_is_closed.restype = ctypes.c_int

    lib.ssh_channel_is_eof.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_is_eof.restype = ctypes.c_int

    lib.ssh_channel_is_open.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_is_open.restype = ctypes.c_int

    lib.ssh_channel_new.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_new.restype = ctypes.c_void_p

    lib.ssh_channel_open_forward.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_channel_open_forward.restype = ctypes.c_int

    lib.ssh_channel_open_session.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_open_session.restype = ctypes.c_int

    lib.ssh_channel_open_x11.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint]
    lib.ssh_channel_open_x11.restype = ctypes.c_int
    
    lib.ssh_channel_poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_channel_poll.restype = ctypes.c_int

    lib.ssh_channel_poll_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.ssh_channel_poll_timeout.restype = ctypes.c_int
     
    lib.ssh_channel_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
    lib.ssh_channel_read.restype = ctypes.c_int

    lib.ssh_channel_read_nonblocking.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
    lib.ssh_channel_read_nonblocking.restype = ctypes.c_int

    lib.ssh_channel_request_env.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ssh_channel_request_env.restype = ctypes.c_int

    lib.ssh_channel_request_exec.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_channel_request_exec.restype = ctypes.c_int

    lib.ssh_channel_request_pty.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_request_pty.restype = ctypes.c_int
 
    lib.ssh_channel_request_pty_size.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.ssh_channel_request_pty_size.restype = ctypes.c_int

    lib.ssh_channel_request_shell.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_request_shell.restype = ctypes.c_int

    lib.ssh_channel_request_send_signal.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_channel_request_send_signal.restype = ctypes.c_int

    lib.ssh_channel_request_sftp.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_request_sftp.restype = ctypes.c_int

    lib.ssh_channel_request_subsystem.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_channel_request_subsystem.restype = ctypes.c_int

    lib.ssh_channel_request_x11.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_channel_request_x11.restype = ctypes.c_int

    lib.ssh_channel_send_eof.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_send_eof.restype = ctypes.c_int

    lib.ssh_channel_select.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_int) ]
    lib.ssh_channel_select.restype = ctypes.c_int

    lib.ssh_channel_set_blocking.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_channel_set_blocking.restype = None
     
    lib.ssh_channel_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint]
    lib.ssh_channel_write.restype = ctypes.c_int
    
    lib.ssh_channel_window_size.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_window_size.restype = ctypes.c_uint

    lib.ssh_basename.argtypes = [ctypes.c_char_p]
    lib.ssh_basename.restype = ctypes.c_char_p

    lib.ssh_clean_pubkey_hash.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.ssh_clean_pubkey_hash.restype = None

    lib.ssh_connect.argtypes = [ctypes.c_void_p]
    lib.ssh_connect.restype = ctypes.c_int

    lib.ssh_copyright.argtypes = [ctypes.c_void_p]
    lib.ssh_copyright.restype = ctypes.c_char_p

    lib.ssh_disconnect.argtypes = [ctypes.c_void_p]
    lib.ssh_disconnect.restype = None

    lib.ssh_dirname.argtypes = [ctypes.c_char_p]
    lib.ssh_dirname.restype = ctypes.c_char_p

    lib.ssh_finalize.argtypes = [ctypes.c_void_p]
    lib.ssh_finalize.restype = ctypes.c_int

    lib.ssh_forward_accept.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_forward_accept.restype = ctypes.c_void_p

    lib.ssh_forward_cancel.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_forward_cancel.restype = ctypes.c_int
    
    lib.ssh_forward_listen.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
    lib.ssh_forward_listen.restype = ctypes.c_int
    
    lib.ssh_free.argtypes = [ctypes.c_void_p]
    lib.ssh_free.restype = None

    lib.ssh_get_disconnect_message.argtypes = [ctypes.c_void_p]
    lib.ssh_get_disconnect_message.restype = ctypes.c_char_p

    lib.ssh_get_error.argtypes = [ctypes.c_void_p]
    lib.ssh_get_error.restype = ctypes.c_char_p

    lib.ssh_get_error_code.argtypes = [ctypes.c_void_p]
    lib.ssh_get_error_code.restype = ctypes.c_int

    lib.ssh_get_fd.argtypes = [ctypes.c_void_p]
    lib.ssh_get_fd.restype = ctypes.c_void_p

    lib.ssh_get_hexa.argtypes = [ctypes.c_char_p, ctypes.c_ulong]
    lib.ssh_get_hexa.restype = ctypes.c_char_p
     
    lib.ssh_get_issue_banner.argtypes = [ctypes.c_void_p]
    lib.ssh_get_issue_banner.restype = ctypes.c_char_p

    lib.ssh_get_openssh_version.argtypes = [ctypes.c_void_p]
    lib.ssh_get_openssh_version.restype = ctypes.c_int

    lib.ssh_get_publickey.argtypes = [ctypes.c_void_p, ctypes.c_void_p] # a verifier
    lib.ssh_get_publickey.restype = ctypes.c_int

    lib.ssh_get_pubkey_hash.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))] 
    lib.ssh_get_pubkey_hash.restype = ctypes.c_int

    lib.ssh_get_random.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int] 
    lib.ssh_get_random.restype = ctypes.c_int

    lib.ssh_get_version.argtypes = [ctypes.c_void_p] 
    lib.ssh_get_version.restype = ctypes.c_int

    lib.ssh_get_status.argtypes = [ctypes.c_void_p] 
    lib.ssh_get_status.restype = ctypes.c_int
    
    lib.ssh_gssapi_get_creds.argtypes = [ctypes.c_void_p]
    lib.ssh_gssapi_get_creds.restype = ctypes.c_void_p

    lib.ssh_gssapi_set_creds.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_gssapi_set_creds.restype = None
    
    lib.ssh_init.argtypes = [] 
    lib.ssh_init.restype = ctypes.c_int

    lib.ssh_is_blocking.argtypes = [ctypes.c_void_p] 
    lib.ssh_is_blocking.restype = ctypes.c_int

    lib.ssh_is_connected.argtypes = [ctypes.c_void_p] 
    lib.ssh_is_connected.restype = ctypes.c_int

    lib.ssh_is_server_known.argtypes = [ctypes.c_void_p] 
    lib.ssh_is_server_known.restype = ctypes.c_int

    lib.ssh_log.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p] 
    lib.ssh_log.restype = None

    lib.ssh_message_channel_request_open_reply_accept.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_channel_request_open_reply_accept.restype = ctypes.c_void_p

    lib.ssh_message_channel_request_reply_success.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_channel_request_reply_success.restype = ctypes.c_int

    lib.ssh_message_free.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_free.restype = None

    lib.ssh_message_free.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_free.restype = ctypes.c_void_p

    lib.ssh_message_subtype.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_subtype.restype = ctypes.c_int

    lib.ssh_message_type.argtypes = [ctypes.c_void_p] 
    lib.ssh_message_type.restype = ctypes.c_int

    lib.ssh_mkdir.argtypes = [ctypes.c_char_p, ctypes.c_void_p] 
    lib.ssh_mkdir.restype = ctypes.c_int

    lib.ssh_new.argtypes = [] 
    lib.ssh_new.restype = ctypes.c_void_p

    lib.ssh_options_copy.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)] 
    lib.ssh_options_copy.restype = ctypes.c_int

    lib.ssh_options_getopt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_char_p)] 
    lib.ssh_options_getopt.restype = ctypes.c_int

    lib.ssh_options_parse_config.argtypes = [ctypes.c_void_p, ctypes.c_char_p] 
    lib.ssh_options_parse_config.restype = ctypes.c_int

    lib.ssh_options_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.ssh_options_set.restype = ctypes.c_int

    lib.ssh_options_get.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
    lib.ssh_options_get.restype = ctypes.c_int

    lib.ssh_options_get_port.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort)]
    lib.ssh_options_get_port.restype = ctypes.c_int
     
    lib.ssh_pcap_file_close.argtypes = [ctypes.c_void_p]
    lib.ssh_pcap_file_close.restype = ctypes.c_int

    lib.ssh_pcap_file_free.argtypes = [ctypes.c_void_p]
    lib.ssh_pcap_file_free.restype = None

    lib.ssh_pcap_file_new.argtypes = []
    lib.ssh_pcap_file_new.restype = ctypes.c_void_p

    lib.ssh_pcap_file_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_pcap_file_open.restype = ctypes.c_int

    lib.ssh_key_new.argtypes = []
    lib.ssh_key_new.restype = ctypes.c_void_p

    lib.ssh_key_free.argtypes = [ctypes.c_void_p]
    lib.ssh_key_free.restype = None

    lib.ssh_key_type.argtypes = [ctypes.c_void_p]
    lib.ssh_key_type.restype = ctypes.c_int

    lib.ssh_key_type_to_char.argtypes = [ctypes.c_int]
    lib.ssh_key_type_to_char.restype = ctypes.c_char_p

    lib.ssh_key_type_from_name.argtypes = [ctypes.c_char_p]
    lib.ssh_key_type_from_name.restype = ctypes.c_int

    lib.ssh_key_is_public.argtypes = [ctypes.c_void_p]
    lib.ssh_key_is_public.restype = ctypes.c_int

    lib.ssh_key_is_private.argtypes = [ctypes.c_void_p]
    lib.ssh_key_is_private.restype = ctypes.c_int

    lib.ssh_key_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.ssh_key_cmp.restype = ctypes.c_int

    lib.ssh_pki_generate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.ssh_pki_generate.restype = ctypes.c_int

    lib.ssh_pki_import_privkey_base64.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_pki_import_privkey_base64.restype = ctypes.c_int

    lib.ssh_pki_import_privkey_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_pki_import_privkey_file.restype = ctypes.c_int
    
    lib.ssh_pki_import_pubkey_base64.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_pki_import_pubkey_base64.restype = ctypes.c_int

    lib.ssh_pki_import_pubkey_file.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_pki_import_pubkey_file.restype = ctypes.c_int

    lib.ssh_pki_export_privkey_to_pubkey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_pki_export_privkey_to_pubkey.restype = ctypes.c_int

    lib.ssh_pki_export_pubkey_base64.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
    lib.ssh_pki_export_pubkey_base64.restype = ctypes.c_int

    lib.ssh_pki_export_pubkey_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_pki_export_pubkey_file.restype = ctypes.c_int

    lib.ssh_print_hexa.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong]
    lib.ssh_print_hexa.restype = None

    lib.ssh_send_ignore.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_send_ignore.restype = ctypes.c_int

    lib.ssh_send_debug.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_send_debug.restype = ctypes.c_int

    lib.ssh_scp_accept_request.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_accept_request.restype = ctypes.c_int

    lib.ssh_scp_close.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_close.restype = ctypes.c_int

    lib.ssh_scp_deny_request.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_scp_deny_request.restype = ctypes.c_int

    lib.ssh_scp_free.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_free.restype = None

    lib.ssh_scp_init.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_init.restype = ctypes.c_int

    lib.ssh_scp_leave_directory.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_leave_directory.restype = ctypes.c_int

    lib.ssh_scp_new.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    lib.ssh_scp_new.restype = ctypes.c_void_p

    lib.ssh_scp_pull_request.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_pull_request.restype = ctypes.c_int

    lib.ssh_scp_push_directory.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_scp_push_directory.restype = ctypes.c_int

    lib.ssh_scp_push_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
    lib.ssh_scp_push_file.restype = ctypes.c_int

    lib.ssh_scp_push_file64.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_int]
    lib.ssh_scp_push_file64.restype = ctypes.c_int

    lib.ssh_scp_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    lib.ssh_scp_read.restype = ctypes.c_int

    lib.ssh_scp_request_get_filename.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_request_get_filename.restype = ctypes.c_char_p

    lib.ssh_scp_request_get_permissions.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_request_get_permissions.restype = ctypes.c_int

    lib.ssh_scp_request_get_size.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_request_get_size.restype = ctypes.c_ulong

    lib.ssh_scp_request_get_size64.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_request_get_size64.restype = ctypes.c_uint

    lib.ssh_scp_request_get_warning.argtypes = [ctypes.c_void_p]
    lib.ssh_scp_request_get_warning.restype = ctypes.c_char_p

    lib.ssh_scp_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    lib.ssh_scp_write.restype = ctypes.c_int
    # to fix later
    timeval = ctypes.c_uint
    lib.ssh_select.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(timeval)]
    lib.ssh_select.restype = ctypes.c_int

    lib.ssh_service_request.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_service_request.restype = ctypes.c_int

    lib.ssh_set_blocking.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_set_blocking.restype = None

    lib.ssh_set_fd_except.argtypes = [ctypes.c_void_p]
    lib.ssh_set_fd_except.restype = None

    lib.ssh_set_fd_toread.argtypes = [ctypes.c_void_p]
    lib.ssh_set_fd_toread.restype = None

    lib.ssh_set_fd_towrite.argtypes = [ctypes.c_void_p]
    lib.ssh_set_fd_towrite.restype = None

    lib.ssh_silent_disconnect.argtypes = [ctypes.c_void_p]
    lib.ssh_silent_disconnect.restype = None

    lib.ssh_set_pcap_file.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_set_pcap_file.restype = ctypes.c_int

    lib.ssh_set_pcap_file.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_set_pcap_file.restype = ctypes.c_int
#*****/USER AUTH/*****
    lib.ssh_userauth_none.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_userauth_none.restype = ctypes.c_int

    lib.ssh_userauth_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_userauth_list.restype = ctypes.c_int

    lib.ssh_userauth_try_publickey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    lib.ssh_userauth_try_publickey.restype = ctypes.c_int
    
    lib.ssh_userauth_publickey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    lib.ssh_userauth_publickey.restype = ctypes.c_int
    #***WIN32***
    lib.ssh_userauth_agent.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssh_userauth_agent.restype = ctypes.c_int
    #***********    
    lib.ssh_userauth_publickey_auto.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ssh_userauth_publickey_auto.restype = ctypes.c_int

    lib.ssh_userauth_password.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ssh_userauth_password.restype = ctypes.c_int

    lib.ssh_userauth_kbdint.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ssh_userauth_kbdint.restype = ctypes.c_int

    lib.ssh_userauth_kbdint_getinstruction.argtypes = [ctypes.c_void_p]
    lib.ssh_userauth_kbdint_getinstruction.restype = ctypes.c_char_p

    lib.ssh_userauth_kbdint_getname.argtypes = [ctypes.c_void_p]
    lib.ssh_userauth_kbdint_getname.restype = ctypes.c_char_p

    lib.ssh_userauth_kbdint_getnprompts.argtypes = [ctypes.c_void_p]
    lib.ssh_userauth_kbdint_getnprompts.restype = ctypes.c_int

    lib.ssh_userauth_kbdint_getprompt.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p]
    lib.ssh_userauth_kbdint_getprompt.restype = ctypes.c_char_p

    lib.ssh_userauth_kbdint_getnanswers.argtypes = [ctypes.c_void_p]
    lib.ssh_userauth_kbdint_getnanswers.restype = ctypes.c_int

    lib.ssh_userauth_kbdint_getanswer.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    lib.ssh_userauth_kbdint_getanswer.restype = ctypes.c_char_p

    lib.ssh_userauth_kbdint_setanswer.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p]
    lib.ssh_userauth_kbdint_setanswer.restype = ctypes.c_int

    lib.ssh_version.argtypes = [ctypes.c_int]
    lib.ssh_version.restype = ctypes.c_char_p

    lib.ssh_write_knownhost.argtypes = [ctypes.c_void_p]
    lib.ssh_write_knownhost.restype = ctypes.c_int

    lib.ssh_string_burn.argtypes = [ctypes.c_void_p]
    lib.ssh_string_burn.restype = None

    lib.ssh_string_copy.argtypes = [ctypes.c_void_p]
    lib.ssh_string_copy.restype = ctypes.c_void_p

    lib.ssh_string_data.argtypes = [ctypes.c_void_p]
    lib.ssh_string_data.restype = None

    lib.ssh_string_fill.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    lib.ssh_string_fill.restype = ctypes.c_int

    lib.ssh_string_free.argtypes = [ctypes.c_void_p]
    lib.ssh_string_free.restype = None

    lib.ssh_string_from_char.argtypes = [ctypes.c_char_p]
    lib.ssh_string_from_char.restype = ctypes.c_void_p

    lib.ssh_string_len.argtypes = [ctypes.c_void_p]
    lib.ssh_string_len.restype = ctypes.c_ulong

    lib.ssh_string_new.argtypes = [ctypes.c_ulong]
    lib.ssh_string_new.restype = ctypes.c_void_p

    lib.ssh_string_get_char.argtypes = [ctypes.c_void_p]
    lib.ssh_string_get_char.restype = ctypes.c_char_p

    lib.ssh_string_to_char.argtypes = [ctypes.c_void_p]
    lib.ssh_string_to_char.restype = ctypes.c_char_p

    lib.ssh_string_free_char.argtypes = [ctypes.c_char_p]
    lib.ssh_string_free_char.restype = None

    lib.ssh_getpass.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int]
    lib.ssh_getpass.restype = ctypes.c_int

    lib.ssh_event_new.argtypes = []
    lib.ssh_event_new.restype = ctypes.c_void_p

    lib.ssh_event_add_fd.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_short, event_cb, ctypes.py_object]
    lib.ssh_event_add_fd.restype = ctypes.c_int

    lib.ssh_event_add_session.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_event_add_session.restype = ctypes.c_int

    lib.ssh_event_dopoll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_event_dopoll.restype = ctypes.c_int

    lib.ssh_event_remove_fd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_event_remove_fd.restype = ctypes.c_int

    lib.ssh_event_remove_session.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_event_remove_session.restype = ctypes.c_int
    
    lib.ssh_event_free.argtypes = [ctypes.c_void_p]
    lib.ssh_event_free.restype = None

    lib.ssh_get_serverbanner.argtypes = [ctypes.c_void_p]
    lib.ssh_get_serverbanner.restype = ctypes.c_char_p
    #*****Server******
    lib.ssh_bind_new.argtypes = []
    lib.ssh_bind_new.restype = ctypes.c_void_p

    lib.ssh_bind_options_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.ssh_bind_options_set.restype = ctypes.c_int

    lib.ssh_bind_listen.argtypes = [ctypes.c_void_p]
    lib.ssh_bind_listen.restype = ctypes.c_int

    lib.ssh_bind_set_callbacks.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_bind_set_callbacks.restype = ctypes.c_int

    lib.ssh_bind_set_blocking.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_bind_set_blocking.restype = None
    
    lib.ssh_bind_get_fd.argtypes = [ctypes.c_void_p]
    lib.ssh_bind_get_fd.restype =  ctypes.c_void_p

    lib.ssh_bind_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_bind_set_fd.restype =  None

    lib.ssh_bind_fd_toaccept.argtypes = [ctypes.c_void_p]
    lib.ssh_bind_fd_toaccept.restype =  None

    lib.ssh_bind_accept.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_bind_accept.restype =  ctypes.c_int

    lib.ssh_bind_accept_fd.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_bind_accept_fd.restype =  ctypes.c_int

    lib.ssh_handle_key_exchange.argtypes = [ctypes.c_void_p]
    lib.ssh_handle_key_exchange.restype =  ctypes.c_int

    lib.ssh_bind_free.argtypes = [ctypes.c_void_p]
    lib.ssh_bind_free.restype =  None

    lib.ssh_set_auth_methods.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_set_auth_methods.restype =  None

    lib.ssh_message_reply_default.argtypes = [ctypes.c_void_p]
    lib.ssh_message_reply_default.restype =  ctypes.c_int

    lib.ssh_message_auth_user.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_user.restype =  ctypes.c_char_p

    lib.ssh_message_auth_password.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_password.restype =  ctypes.c_char_p

    lib.ssh_message_auth_pubkey.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_pubkey.restype =  ctypes.c_void_p

    lib.ssh_message_auth_kbdint_is_response.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_kbdint_is_response.restype =  ctypes.c_int

    lib.ssh_message_auth_publickey_state.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_publickey_state.restype =  ctypes.c_int

    lib.ssh_message_auth_reply_success.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_message_auth_reply_success.restype =  ctypes.c_int

    lib.ssh_message_auth_reply_pk_ok.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_message_auth_reply_pk_ok.restype =  ctypes.c_int

    lib.ssh_message_auth_reply_pk_ok_simple.argtypes = [ctypes.c_void_p]
    lib.ssh_message_auth_reply_pk_ok_simple.restype =  ctypes.c_int
    
    lib.ssh_message_auth_set_methods.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_message_auth_set_methods.restype =  ctypes.c_int

    lib.ssh_message_auth_interactive_request.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_message_auth_interactive_request.restype =  ctypes.c_int

    lib.ssh_message_service_reply_success.argtypes = [ctypes.c_void_p]
    lib.ssh_message_service_reply_success.restype =  ctypes.c_int

    lib.ssh_message_service_service.argtypes = [ctypes.c_void_p]
    lib.ssh_message_service_service.restype =  ctypes.c_char_p

    lib.ssh_message_global_request_reply_success.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    lib.ssh_message_global_request_reply_success.restype =  ctypes.c_int

    lib.ssh_set_message_callback.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_set_message_callback.restype = None

    lib.ssh_execute_message_callbacks.argtypes = [ctypes.c_void_p]
    lib.ssh_execute_message_callbacks.restype =  ctypes.c_int

    lib.ssh_message_channel_request_open_originator.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_open_originator.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_open_originator_port.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_open_originator_port.restype =  ctypes.c_int
  
    lib.ssh_message_channel_request_open_destination.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_open_destination.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_open_destination_port.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_open_destination_port.restype =  ctypes.c_int

    lib.ssh_message_channel_request_channel.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_channel.restype =  ctypes.c_void_p

    lib.ssh_message_channel_request_pty_term.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_pty_term.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_pty_width.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_pty_width.restype =  ctypes.c_int

    lib.ssh_message_channel_request_pty_height.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_pty_height.restype =  ctypes.c_int

    lib.ssh_message_channel_request_pty_pxwidth.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_pty_pxwidth.restype =  ctypes.c_int

    lib.ssh_message_channel_request_pty_pxheight.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_pty_pxheight.restype =  ctypes.c_int

    lib.ssh_message_channel_request_env_name.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_env_name.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_env_value.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_env_value.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_command.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_command.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_subsystem.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_subsystem.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_x11_single_connection.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_x11_single_connection.restype =  ctypes.c_int

    lib.ssh_message_channel_request_x11_auth_protocol.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_x11_auth_protocol.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_x11_auth_cookie.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_x11_auth_cookie.restype =  ctypes.c_char_p

    lib.ssh_message_channel_request_x11_screen_number.argtypes = [ctypes.c_void_p]
    lib.ssh_message_channel_request_x11_screen_number.restype =  ctypes.c_int

    lib.ssh_message_global_request_address.argtypes = [ctypes.c_void_p]
    lib.ssh_message_global_request_address.restype =  ctypes.c_char_p

    lib.ssh_message_global_request_port.argtypes = [ctypes.c_void_p]
    lib.ssh_message_global_request_port.restype =  ctypes.c_int

    lib.ssh_channel_open_auth_agent.argtypes = [ctypes.c_void_p]
    lib.ssh_channel_open_auth_agent.restype =  ctypes.c_int
    
    lib.ssh_channel_open_reverse_forward.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_channel_open_reverse_forward.restype =  ctypes.c_int

    lib.ssh_channel_open_x11.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.ssh_channel_open_x11.restype =  ctypes.c_int

    lib.ssh_channel_request_send_exit_status.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ssh_channel_request_send_exit_status.restype =  ctypes.c_int

    lib.ssh_channel_request_send_exit_signal.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
    lib.ssh_channel_request_send_exit_signal.restype =  ctypes.c_int

    lib.ssh_channel_write_stderr.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    lib.ssh_channel_write_stderr.restype =  ctypes.c_int

    lib.ssh_accept.argtypes = [ctypes.c_void_p]
    lib.ssh_accept.restype =  ctypes.c_int

    lib.ssh_set_agent_channel.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ssh_set_agent_channel.restype =  ctypes.c_int
    
    lib.channel_write_stderr.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    lib.channel_write_stderr.restype =  ctypes.c_int
    #*****callbacks******
    lib.ssh_set_server_callbacks.argtypes = [ctypes.c_void_p, ctypes.POINTER(ssh_server_callbacks_struct)]
    lib.ssh_set_server_callbacks.restype =  ctypes.c_int

    lib.ssh_set_callbacks.argtypes = [ctypes.c_void_p, ctypes.POINTER(ssh_callbacks_struct)]
    lib.ssh_set_callbacks.restype =  ctypes.c_int

    lib.ssh_set_channel_callbacks.argtypes = [ctypes.c_void_p, ctypes.POINTER(ssh_channel_callbacks_struct)]
    lib.ssh_set_channel_callbacks.restype =  ctypes.c_int

    lib.ssh_threads_set_callbacks.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.ssh_threads_set_callbacks.restype =  ctypes.c_int

    lib.sftp_server_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.sftp_server_new.restype = ctypes.c_void_p
    
    lib.sftp_server_init.argtypes = [ctypes.c_void_p]
    lib.sftp_server_init.restype = ctypes.c_int
    
    lib.sftp_free.argtypes = [ctypes.c_void_p]
    lib.sftp_free.restype = None
    
    lib.sftp_init.argtypes = [ctypes.c_void_p]
    lib.sftp_init.restype = ctypes.c_int
    
    lib.sftp_new.argtypes = [ctypes.c_void_p]
    lib.sftp_new.restype = ctypes.c_void_p
    
    lib.sftp_new_channel.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.sftp_new_channel.restype = ctypes.c_void_p    
    
    lib.sftp_get_client_message.argtypes = [ctypes.c_void_p]
    lib.sftp_get_client_message.restype = ctypes.c_void_p
    
    lib.sftp_client_message_free.argtypes = [ctypes.c_void_p] 
    lib.sftp_client_message_free.restype = None
    
    lib.sftp_client_message_get_type.argtypes = [ctypes.c_void_p]
    lib.sftp_client_message_get_type.restype = ctypes.c_ubyte
    
    lib.sftp_client_message_get_filename.argtypes = [ctypes.c_void_p]
    lib.sftp_client_message_get_filename.restype = ctypes.c_char_p
    
    lib.sftp_client_message_set_filename.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.sftp_client_message_set_filename.restype = None
    
    lib.sftp_client_message_get_data.argtypes = [ctypes.c_void_p]
    lib.sftp_client_message_get_data.restype = ctypes.c_char_p

    lib.sftp_client_message_get_flags.argtypes = [ctypes.c_void_p]
    lib.sftp_client_message_get_flags.restype = ctypes.c_uint
    
    lib.sftp_send_client_message.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.sftp_send_client_message.restype = ctypes.c_int
    
except AttributeError:
    lib = None
    raise ImportError('ssh shared library not found or incompatible')
except (OSError, IOError):
    lib = None
    raise ImportError('ssh shared library not found.\n'
                      'you probably had not installed libssh library.\n')
