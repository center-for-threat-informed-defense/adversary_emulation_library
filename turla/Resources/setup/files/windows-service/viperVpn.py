"""
# ---------------------------------------------------------------------------
# viperVpn.py - viperVpn Windows service for scenario. Cobbled together from examples, including: https://metallapan.se/post/windows-service-pywin32-pyinstaller/.

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: viperVpn.py

# ---------------------------------------------------------------------------

# Prerequisites:
* create venv
* activate venv
* pip3 install pywin32 pyinstaller
* run post-install pyinstaller
* deactivate venv
* activate venv (yes, necessary)

# Build:
pyinstaller.exe --onefile --runtime-tmpdir=. --hidden-import win32timezone viperVpn.py

# With Administrator privileges
# Install:
dist\mviperVpn.exe install

# Start:
dist\viperVpn.exe start

# Install with autostart:
dist\viperVpn.exe --startup delayed install

# Debug:
dist\viperVpn.exe debug

# Stop:
dist\viperVpn.exe stop

# Uninstall:
dist\viperVpn.exe remove


"""

import time

import win32serviceutil  # ServiceFramework and commandline helper
import win32service  # Events
import servicemanager  # Simple setup and logging

class MyService:
    """Silly little application stub"""
    def stop(self):
        """Stop the service"""
        self.running = False

    def run(self):
        """Main service loop. This is where work is done!"""
        self.running = True
        while self.running:
            time.sleep(10)  # Important work
            # servicemanager.LogInfoMsg("Service running...")


class MyServiceFramework(win32serviceutil.ServiceFramework):

    _svc_name_ = 'ViperVPNSvc'
    _svc_display_name_ = 'Viper VPN Service'
    _svc_description_ = 'Enterprise VPN connectivity platform providing secure access to your private intranet. Requires active organization subscription. Contact your IT administrator for more information.'

    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.service_impl.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """Start the service; does not return until stopped"""
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        self.service_impl = MyService()
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        # Run the service
        self.service_impl.run()


def init():
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(MyServiceFramework)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(MyServiceFramework)


if __name__ == '__main__':
    init()
