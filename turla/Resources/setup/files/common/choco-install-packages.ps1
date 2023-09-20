# ---------------------------------------------------------------------------
# choco-install-packages.ps1 - install packages with chocolatey

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: choco-install-packages.ps1

# ---------------------------------------------------------------------------

# This script holds the packages necessary to execute (Only some of these were used on each machine, but having them alll installed should not effect execution)
choco install -y --limit-output --no-progress sysinternals  # Needed to disable defender

# Non-required Quality of life tools
# File editor, alternative to IE
choco install -y --limit-output --no-progress vscode microsoft-edge
