'''
Windows Service Class for PKNS
'''

__version__ = "0.0.1-Windows"
__author__ = "Om Belote ,Anubhav Mattoo"

import servicemanager
import win32event
import win32service
from win32.lib import win32serviceutil


class Service_Base(win32serviceutil.ServiceFramework):
    """
    Windows 32 service API
    """
    _svc_name_ = 'enchanto'
    _svc_display_name_ = 'rigged'
    _svc_description_ = 'lol'

    def __init__(self, target, *args, **kwargs):
        self.target = target
        self.wait = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        '''
        Stop windows service
        '''
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.wait)

    def SvcDoStart(self):
        '''
        Start Windows Service
        '''
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ""))
        self.target()

    @classmethod
    def cmd_line_parser(cls):
        '''
        Command line parser
        '''
        win32serviceutil.HandleCommandLine(cls)
