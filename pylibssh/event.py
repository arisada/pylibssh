from . import api
from api import lib

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
        self.event = lib.ssh_event_new()
    def __del__(self):
        if (self.event is not None):
            lib.ssh_event_free(self.event)
            self.event=None
    def addSession(self, session):
        lib.ssh_event_add_session(self.event, session.session)
    def removeSession(self, session):
        lib.ssh_event_remove_session(self.event, session.session)
    def doPoll(self, timeout=-1):
        rc = lib.ssh_event_dopoll(self.event, timeout)
        if (rc == SSH_ERROR):
            raise RuntimeError("event_dopoll failed")
        return rc
    def addFd(self, fdcallback, events):
        lib.ssh_event_add_fd(self.event, fdcallback.fd.fileno(), events, _event_cb_object, fdcallback)
    def removeFd(self, fd):
        lib.ssh_event_remove_fd(self.event, fd)
