'''
Windows Service Class for PKNS
'''

__version__ = "0.0.10-Windows"
__author__ = "Om Belote"
__credits__ = ['Anubhav Mattoo']

import servicemanager
import win32event
import win32service
from win32.lib import win32serviceutil


class Service_Base(win32serviceutil.ServiceFramework):
    """
    Windows 32 Service API
    """
    _svc_name_ = 'pkns_server'
    _svc_display_name_ = 'PKNS Server'
    _svc_description_ = 'PKNS Service'
    def __init__(self, name, worker, description):
        self.__name__ = name
        self.target = worker
        self.wait = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        '''
        Stop Windows Service
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
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

    @classmethod
    def cmd_line_parser(cls):
        '''
        Command Line Parser
        '''
        win32serviceutil.HandleCommandLine(cls)
