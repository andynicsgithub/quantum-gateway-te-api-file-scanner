#!/usr/bin/env python3

r"""
service_wrapper.py v11.2 (alpha)
Windows Service wrapper for TE API Scanner Watcher.

This module wraps the TE API Scanner to run as a Windows Service.
It uses the Network Service account by default for security.

Usage:
    Install: python service_wrapper.py install
    Start:   sc start TEWatcher
    Stop:    sc stop TEWatcher
    Remove:  python service_wrapper.py remove

Configuration:
    The service runs te_api.py --watch with optional command-line arguments.
    Configure using sc config:
    sc config TEWatcher binPath= "py.exe C:\te_api\service_wrapper.py --watch --ip <appliance-ip>"

Security:
    - Runs as Network Service by default (limited privileges)
    - Can be configured to run as specific user for network share access
    - Immediate shutdown on service stop (no graceful batch completion)
"""

import os
import threading

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError as e:
    raise ImportError(
        f"{e.name} is required for Windows service mode. "
        f"Install pywin32: pip install pywin32"
    )


class TEWatcherService(win32serviceutil.ServiceFramework):
    """
    Windows Service wrapper for TE API Scanner.

    Service Name: TEWatcher
    Display Name: Threat Emulation Watcher
    Account: Network Service (default) or configured user
    """

    _service_name = "TEWatcher"
    _display_name = "Threat Emulation Watcher"
    _description = "Monitors input directory for files to scan via Threat Emulation API. Runs in continuous watch mode with automatic batch processing."

    # Service account (None = uses Network Service by default)
    _username = None
    _password = None

    def __init__(self, args):
        """
        Initialize service.

        Args:
            args: Command-line arguments passed to service
        """
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = threading.Event()

    def SvcStop(self):
        """
        Handle service stop request.
        Immediate stop (as per requirements - no graceful batch completion).
        """
        self.stop_event.set()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """
        Main service run loop.
        """
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PY_SERVICE_STARTED,
            ("%s" % self._service_name),
        )

        try:
            # Change to script directory so config.ini is found
            script_dir = os.path.dirname(os.path.abspath(__file__))
            os.chdir(script_dir)

            # Import te_api and run main with watch mode
            import te_api

            # Run main - this will enter watch mode and block until stopped
            te_api.main(stop_event=self.stop_event)

        except Exception as e:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_ERROR_TYPE,
                servicemanager.PY_SERVICE_FAILED,
                ("%s: %s" % (self._service_name, str(e))),
            )
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)


def main():
    """
    Entry point for service management.

    Supported commands:
        install - Install the service
        remove - Remove the service
        start - Start the service
        stop - Stop the service
    """
    win32serviceutil.HandleCommandLine(TEWatcherService)


if __name__ == "__main__":
    main()
