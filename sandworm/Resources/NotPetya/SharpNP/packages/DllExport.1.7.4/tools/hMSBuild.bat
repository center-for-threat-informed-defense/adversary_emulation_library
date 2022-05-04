@echo off
:: hMSBuild - 2.3.0.59567+cf86a84
:: Copyright (c) 2017-2020  Denis Kuzmin [ x-3F@outlook.com ] GitHub/3F
:: Copyright (c) the hMSBuild contributors
set "aa=%~dp0"
set ab=%*
if not defined ab setlocal enableDelayedExpansion & goto bt
if not defined __p_call set ab=%ab:^=^^%
set ac=%ab:!= #__b_ECL## %
set ac=%ac:^= #__b_CRT## %
setlocal enableDelayedExpansion
set "ad=^"
set "ac=!ac:%%=%%%%!"
set "ac=!ac:&=%%ad%%&!"
:bt
set "ae=2.8.4"
set af=%temp%\hMSBuild_vswhere
set "ag="
set "ah="
set "ai="
set "aj="
set "ak="
set "al="
set "am="
set "an="
set "ao="
set "ap="
set "aq="
set "ar="
set "as="
set /a at=0
if not defined ab goto bu
set ac=!ac:/?=/h!
call :bv bo ac bp
goto bw
:bx
echo.
@echo hMSBuild 2.3.0.59567+cf86a84
@echo Copyright (c) 2017-2020  Denis Kuzmin [ x-3F@outlook.com ] GitHub/3F
@echo Copyright (c) hMSBuild contributors
echo.
echo Licensed under the MIT License
@echo https://github.com/3F/hMSBuild
echo.
@echo.
@echo Usage: hMSBuild [args to hMSBuild] [args to msbuild.exe or GetNuTool core]
echo ------
echo.
echo Arguments:
echo ----------
echo  -no-vs        - Disable searching from Visual Studio.
echo  -no-netfx     - Disable searching from .NET Framework.
echo  -no-vswhere   - Do not search via vswhere.
echo.
echo  -vsw-priority {IDs} - Non-strict components preference: C++ etc.
echo                        Separated by space: https://aka.ms/vs/workloads
echo.
echo  -vsw-version {arg}  - Specific version of vswhere. Where {arg}:
echo      * 2.6.7 ...
echo      * Keywords:
echo        `latest` - To get latest remote version;
echo        `local`  - To use only local versions;
echo                   (.bat;.exe /or from +15.2.26418.1 VS-build)
echo.
echo  -no-cache         - Do not cache vswhere for this request.
echo  -reset-cache      - To reset all cached vswhere versions before processing.
echo  -notamd64         - To use 32bit version of found msbuild.exe if it's possible.
echo  -stable           - It will ignore possible beta releases in last attempts.
echo  -eng              - Try to use english language for all build messages.
echo  -GetNuTool {args} - Access to GetNuTool core. https://github.com/3F/GetNuTool
echo  -only-path        - Only display fullpath to found MSBuild.
echo  -force            - Aggressive behavior for -vsw-priority, -notamd64, etc.
echo  -vsw-as "args..." - Reassign default commands to vswhere if used.
echo  -debug            - To show additional information from hMSBuild.
echo  -version          - Display version of hMSBuild.
echo  -help             - Display this help. Aliases: -help -h
echo.
echo.
echo ------
echo Flags:
echo ------
echo  __p_call - Tries to eliminate the difference for the call-type invoking %~nx0
echo.
echo --------
echo Samples:
echo --------
echo hMSBuild -notamd64 -vsw-version 2.6.7 "Conari.sln" /t:Rebuild
echo hMSBuild -vsw-version latest "Conari.sln"
echo.
echo hMSBuild -no-vswhere -no-vs -notamd64 "Conari.sln"
echo hMSBuild -no-vs "DllExport.sln"
echo hMSBuild vsSolutionBuildEvent.sln
echo.
echo hMSBuild -GetNuTool -unpack
echo hMSBuild -GetNuTool /p:ngpackages="Conari;regXwild"
echo.
echo hMSBuild -no-vs "DllExport.sln" ^|^| goto by
goto bz
:bw
set "au="
set /a av=0
:b0
set aw=!bo[%av%]!
if [!aw!]==[-help] ( goto bx ) else if [!aw!]==[-h] ( goto bx ) else if [!aw!]==[-?] ( goto bx )
if [!aw!]==[-nocachevswhere] (
call :b1 -nocachevswhere -no-cache -reset-cache
set aw=-no-cache
) else if [!aw!]==[-novswhere] (
call :b1 -novswhere -no-vswhere
set aw=-no-vswhere
) else if [!aw!]==[-novs] (
call :b1 -novs -no-vs
set aw=-no-vs
) else if [!aw!]==[-nonet] (
call :b1 -nonet -no-netfx
set aw=-no-netfx
) else if [!aw!]==[-vswhere-version] (
call :b1 -vswhere-version -vsw-version
set aw=-vsw-version
)
if [!aw!]==[-debug] (
set am=1
goto b2
) else if [!aw!]==[-GetNuTool] (
call :b3 "accessing to GetNuTool ..."
for /L %%p IN (0,1,8181) DO (
if "!escg:~%%p,10!"=="-GetNuTool" (
set ax=!escg:~%%p!
call :b4 !ax:~10!
set /a at=%ERRORLEVEL%
goto bz
)
)
call :b3 "!aw! is corrupted: !escg!"
set /a at=1
goto bz
) else if [!aw!]==[-no-vswhere] (
set aj=1
goto b2
) else if [!aw!]==[-no-cache] (
set ak=1
goto b2
) else if [!aw!]==[-reset-cache] (
set al=1
goto b2
) else if [!aw!]==[-no-vs] (
set ah=1
goto b2
) else if [!aw!]==[-no-netfx] (
set ai=1
goto b2
) else if [!aw!]==[-notamd64] (
set ag=1
goto b2
) else if [!aw!]==[-only-path] (
set an=1
goto b2
) else if [!aw!]==[-eng] (
chcp 437 >nul
goto b2
) else if [!aw!]==[-vsw-version] ( set /a "av+=1" & call :b5 bo[!av!] v
set ae=!v!
call :b3 "selected vswhere version:" v
set ao=1
goto b2
) else if [!aw!]==[-version] (
@echo 2.3.0.59567+cf86a84
goto bz
) else if [!aw!]==[-vsw-priority] ( set /a "av+=1" & call :b5 bo[!av!] v
set ap=!v!
goto b2
) else if [!aw!]==[-vsw-as] ( set /a "av+=1" & call :b5 bo[!av!] v
set aq=!v!
goto b2
) else if [!aw!]==[-stable] (
set ar=1
goto b2
) else if [!aw!]==[-force] (
set as=1
goto b2
) else (
call :b3 "non-handled key:" bo{%av%}
set au=!au! !bo{%av%}!
)
:b2
set /a "av+=1" & if %av% LSS !bp! goto b0
:bu
if defined al (
call :b3 "resetting vswhere cache"
rmdir /S/Q "%af%" 2>nul
)
if not defined aj if not defined ah (
call :b6 bq
if defined bq goto b7
)
if not defined ah (
call :b8 bq
if defined bq goto b7
)
if not defined ai (
call :b9 bq
if defined bq goto b7
)
echo MSBuild tools was not found. Use `-debug` key for details.
set /a at=2
goto bz
:b7
if defined an (
echo !bq!
goto bz
)
set ay="!bq!"
echo hMSBuild: !ay!
if not defined au goto b_
set au=%au: #__b_CRT## =^%
set au=%au: #__b_ECL## =^!%
set au=!au: #__b_EQ## ==!
:b_
call :b3 "Arguments: " au
!ay! !au!
set /a at=%ERRORLEVEL%
goto bz
:bz
exit/B !at!
:b6
call :b3 "trying via vswhere..."
if defined ao if not "!ae!"=="local" (
call :ca a5 az
call :cb a5 br az
set %1=!br!
exit/B 0
)
call :cc a5
set "az="
if not defined a5 (
if "!ae!"=="local" (
set "%1=" & exit/B 2
)
call :ca a5 az
)
call :cb a5 br az
set %1=!br!
exit/B 0
:cc
set a0=!aa!vswhere
call :cd a0 bs
if defined bs set "%1=!a0!" & exit/B 0
set a1=Microsoft Visual Studio\Installer
if exist "%ProgramFiles(x86)%\!a1!" set "%1=%ProgramFiles(x86)%\!a1!\vswhere" & exit/B 0
if exist "%ProgramFiles%\!a1!" set "%1=%ProgramFiles%\!a1!\vswhere" & exit/B 0
call :b3 "local vswhere is not found."
set "%1="
exit/B 3
:ca
if defined ak (
set a2=!af!\_mta\%random%%random%vswhere
) else (
set a2=!af!
if defined ae (
set a2=!a2!\!ae!
)
)
call :b3 "tvswhere: " a2
if "!ae!"=="latest" (
set a3=vswhere
) else (
set a3=vswhere/!ae!
)
set a4=/p:ngpackages="!a3!:vswhere" /p:ngpath="!a2!"
call :b3 "GetNuTool call: " a4
setlocal
set __p_call=1
if defined am (
call :b4 !a4!
) else (
call :b4 !a4! >nul
)
endlocal
set "%1=!a2!\vswhere\tools\vswhere"
set "%2=!a2!"
exit/B 0
:cb
set "a5=!%1!"
set "a6=!%3!"
call :cd a5 a5
if not defined a5 (
call :b3 "vswhere tool does not exist"
set "%2=" & exit/B 1
)
call :b3 "vswbin: " a5
set "a7="
set "a8="
set a9=!ap!
if not defined aq set aq=-products * -latest
call :b3 "assign command: " aq
:ce
call :b3 "attempts with filter: " a9 a7
set "a_=" & set "ba="
for /F "usebackq tokens=1* delims=: " %%a in (`"!a5!" -nologo !a7! -requires !a9! Microsoft.Component.MSBuild !aq!`) do (
if /I "%%~a"=="installationPath" set a_=%%~b
if /I "%%~a"=="installationVersion" set ba=%%~b
if defined a_ if defined ba (
call :cf a_ ba a8
if defined a8 goto cg
set "a_=" & set "ba="
)
)
if not defined ar if not defined a7 (
set a7=-prerelease
goto ce
)
if defined a9 (
set bb=Tools was not found for: !a9!
if defined as (
call :b3 "Ignored via -force. !bb!"
set "a8=" & goto cg
)
call :ch "!bb!"
set "a9=" & set "a7="
goto ce
)
:cg
if defined a6 if defined ak (
call :b3 "reset vswhere " a6
rmdir /S/Q "!a6!"
)
set %2=!a8!
exit/B 0
:cf
set a_=!%1!
set ba=!%2!
call :b3 "vspath: " a_
call :b3 "vsver: " ba
if not defined ba (
call :b3 "nothing to see via vswhere"
set "%3=" & exit/B 3
)
for /F "tokens=1,2 delims=." %%a in ("!ba!") do (
set ba=%%~a.0
)
if !ba! geq 16 set ba=Current
if not exist "!a_!\MSBuild\!ba!\Bin" set "%3=" & exit/B 3
set bc=!a_!\MSBuild\!ba!\Bin
call :b3 "found path via vswhere: " bc
if exist "!bc!\amd64" (
call :b3 "found /amd64"
set bc=!bc!\amd64
)
call :ci bc bc
set %3=!bc!
exit/B 0
:b8
call :b3 "Searching from Visual Studio - 2015, 2013, ..."
for %%v in (14.0, 12.0) do (
call :cj %%v Y & if defined Y (
set %1=!Y!
exit/B 0
)
)
call :b3 "-vs: not found"
set "%1="
exit/B 0
:b9
call :b3 "Searching from .NET Framework - .NET 4.0, ..."
for %%v in (4.0, 3.5, 2.0) do (
call :cj %%v Y & if defined Y (
set %1=!Y!
exit/B 0
)
)
call :b3 "-netfx: not found"
set "%1="
exit/B 0
:cj
call :b3 "check %1"
for /F "usebackq tokens=2* skip=2" %%a in (
`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSBuild\ToolsVersions\%1" /v MSBuildToolsPath 2^> nul`
) do if exist %%b (
set bc=%%~b
call :b3 ":msbfound " bc
call :ci bc br
set %2=!br!
exit/B 0
)
set "%2="
exit/B 0
:ci
set bc=!%~1!\MSBuild.exe
set %2=!bc!
if not defined ag (
exit/B 0
)
set bd=!bc:Framework64=Framework!
set bd=!bd:\amd64=!
if exist "!bd!" (
call :b3 "Return 32bit version because of -notamd64 key."
set %2=!bd!
exit/B 0
)
if defined as (
call :b3 "Ignored via -force. Only 64bit version was found for -notamd64"
set "%2=" & exit/B 0
)
call :ch "Return 64bit version. Found only this."
exit/B 0
:cd
call :b3 "bat/exe: " %1
if exist "!%1!.bat" set %2="!%1!.bat" & exit/B 0
if exist "!%1!.exe" set %2="!%1!.exe" & exit/B 0
set "%2="
exit/B 0
:b1
call :ch "'%~1' is obsolete. Use alternative: %~2 %~3"
exit/B 0
:ch
echo   [*] WARN: %~1
exit/B 0
:b3
if defined am (
set be=%1
set be=!be:~0,-1!
set be=!be:~1!
echo.[%TIME% ] !be! !%2! !%3!
)
exit/B 0
:bv
set bf=!%2!
:ck
for /F "tokens=1* delims==" %%a in ("!bf!") do (
if "%%~b"=="" (
call :cl %1 !bf! %3
exit/B 0
)
set bf=%%a #__b_EQ## %%b
)
goto ck
:cl
set "bg=%~1"
set /a av=-1
:cm
set /a av+=1
set %bg%[!av!]=%~2
set %bg%{!av!}=%2
shift & if not "%~3"=="" goto cm
set /a av-=1
set %1=!av!
exit/B 0
:b5
set bh=!%1!
set "bh=%bh: #__b_CRT## =^%"
set "bh=%bh: #__b_ECL## =^!%"
set bh=!bh: #__b_EQ## ==!
set %2=!bh!
exit/B 0
:b4
setlocal disableDelayedExpansion
@echo off
:: GetNuTool - Executable version
:: Copyright (c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ]
:: https://github.com/3F/GetNuTool
set bi=gnt.core
set bj="%temp%\%random%%random%%bi%"
if "%~1"=="-unpack" goto cn
set bk=%*
if defined __p_call if defined bk set bk=%bk:^^=^%
set bl=%__p_msb%
if defined bl goto co
if "%~1"=="-msbuild" goto cp
for %%v in (4.0, 14.0, 12.0, 3.5, 2.0) do (
for /F "usebackq tokens=2* skip=2" %%a in (
`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSBuild\ToolsVersions\%%v" /v MSBuildToolsPath 2^> nul`
) do if exist %%b (
set bl="%%~b\MSBuild.exe"
goto co
)
)
echo MSBuild was not found. Try -msbuild "fullpath" args 1>&2
exit/B 2
:cp
shift
set bl=%1
shift
set bm=%bk:!= #__b_ECL## %
setlocal enableDelayedExpansion
set bm=!bm:%%=%%%%!
:cq
for /F "tokens=1* delims==" %%a in ("!bm!") do (
if "%%~b"=="" (
call :cr !bm!
exit/B %ERRORLEVEL%
)
set bm=%%a #__b_EQ## %%b
)
goto cq
:cr
shift & shift
set "bk="
:cs
set bk=!bk! %1
shift & if not "%~2"=="" goto cs
set bk=!bk: #__b_EQ## ==!
setlocal disableDelayedExpansion
set bk=%bk: #__b_ECL## =!%
:co
call :ct
call %bl% %bj% /nologo /p:wpath="%cd%/" /v:m /m:4 %bk%
set "bl="
set bn=%ERRORLEVEL%
del /Q/F %bj%
exit/B %bn%
:cn
set bj="%cd%\%bi%"
echo Generating minified version in %bj% ...
:ct
<nul set /P ="">%bj%
set a=PropertyGroup&set b=Condition&set c=ngpackages&set d=Target&set e=DependsOnTargets&set f=TaskCoreDllPath&set g=MSBuildToolsPath&set h=UsingTask&set i=CodeTaskFactory&set j=ParameterGroup&set k=Reference&set l=Include&set m=System&set n=Using&set o=Namespace&set p=IsNullOrEmpty&set q=return&set r=string&set s=delegate&set t=foreach&set u=WriteLine&set v=Combine&set w=Console.WriteLine&set x=Directory&set y=GetNuTool&set z=StringComparison&set _=EXT_NUSPEC
<nul set /P =^<!-- GetNuTool - github.com/3F/GetNuTool --^>^<!-- Copyright (c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ] --^>^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>^<%a%^>^<ngconfig %b%="'$(ngconfig)'==''"^>packages.config^</ngconfig^>^<ngserver %b%="'$(ngserver)'==''"^>https://www.nuget.org/api/v2/package/^</ngserver^>^<%c% %b%="'$(%c%)'==''"^>^</%c%^>^<ngpath %b%="'$(ngpath)'==''"^>packages^</ngpath^>^</%a%^>^<%d% Name="get" BeforeTargets="Build" %e%="header"^>^<a^>^<Output PropertyName="plist" TaskParameter="Result"/^>^</a^>^<b plist="$(plist)"/^>^</%d%^>^<%d% Name="pack" %e%="header"^>^<c/^>^</%d%^>^<%a%^>^<%f% %b%="Exists('$(%g%)\Microsoft.Build.Tasks.v$(MSBuildToolsVersion).dll')"^>$(%g%)\Microsoft.Build.Tasks.v$(MSBuildToolsVersion).dll^</%f%^>^<%f% %b%="'$(%f%)'=='' and Exists('$(%g%)\Microsoft.Build.Tasks.Core.dll')"^>$(%g%)\Microsoft.Build.Tasks.Core.dll^</%f%^>^</%a%^>^<%h% TaskName="a" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<%j%^>^<Result Output="true"/^>^</%j%^>^<Task^>^<%k% %l%="%m%.Xml"/^>^<%k% %l%="%m%.Xml.Linq"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.Collections.Generic"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.Xml.Linq"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngconfig)";var b=@"$(%c%)";var c=@"$(wpath)";if(!String.%p%(b)){Result=b;%q% true;}var d=Console.Error;Action^<%r%,Queue^<%r%^>^>e=%s%(%r% f,Queue^<%r%^>g){%t%(var h in XDocument.Load(f).Descendants("package")){var i=h.Attribute("id");var j=h.Attribute("version");var k=h.Attribute("output");if(i==null){d.%u%("'id' does not exist in '{0}'",f);%q%;}var l=i.Value;if(j!=null){l+="/"+j.Value;}if(k!=null){g.Enqueue(l+":"+k.Value);continue;}g.Enqueue(l);}};var m=new Queue^<%r%^>();%t%(var f in a.Split(new char[]{a.IndexOf('^|')!=-1?'^|':';'},(StringSplitOptions)1))>>%bj%
<nul set /P ={var n=Path.%v%(c,f);if(File.Exists(n)){e(n,m);}else{d.%u%(".config '{0}' is not found.",n);}}if(m.Count^<1){d.%u%("Empty list. Use .config or /p:%c%\n");}else{Result=%r%.Join("|",m.ToArray());}]]^>^</Code^>^</Task^>^</%h%^>^<%h% TaskName="b" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<%j%^>^<plist/^>^</%j%^>^<Task^>^<%k% %l%="WindowsBase"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.IO.Packaging"/^>^<%n% %o%="%m%.Net"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngserver)";var b=@"$(wpath)";var c=@"$(ngpath)";var d=@"$(proxycfg)".Trim();var e=@"$(debug)"=="true";if(plist==null){%q% false;}ServicePointManager.SecurityProtocol^|=SecurityProtocolType.Tls11^|SecurityProtocolType.Tls12;var f=new %r%[]{"/_rels/","/package/","/[Content_Types].xml"};Action^<%r%,object^>g=%s%(%r% h,object i){if(e){%w%(h,i);}};Func^<%r%,WebProxy^>j=%s%(%r% k){var l=k.Split('@');if(l.Length^<=1){%q% new WebProxy(l[0],false);}var m=l[0].Split(':');%q% new WebProxy(l[1],false){Credentials=new NetworkCredential(m[0],(m.Length^>1)?m[1]:null)};};Func^<%r%,%r%^>n=%s%(%r% i){%q% Path.%v%(b,i??"");};Action^<%r%,%r%,%r%^>o=%s%(%r% p,%r% q,%r% r){var s=Path.GetFullPath(n(r??q));if(%x%.Exists(s)){%w%("`{0}` was found in \"{1}\"",q,s);%q%;}Console.Write("Getting `{0}` ... ",p);var t=Path.%v%(Path.GetTempPath(),Guid.NewGuid().ToString());using(var u=new WebClient()){try{if(!String.%p%(d)){u.Proxy=j(d);}u.Headers.Add("User-Agent","%y% $(%y%)");u.UseDefaultCredentials=true;if(u.Proxy.Credentials==null){u.Proxy.Credentials=CredentialCache.DefaultCredentials;}u.DownloadFile(a+p,t);}catch(Exception v){Console.Error.%u%(v.Message);%q%;}}%w%("Extracting into \"{0}\"",s);using(var w=ZipPackage.Open(t,FileMode.Open,FileAccess.Read)){%t%(var x in w.GetParts()){var y=Uri.UnescapeDataString(x.Uri.OriginalString);if>>%bj%
<nul set /P =(f.Any(z=^>y.StartsWith(z,%z%.Ordinal))){continue;}var _=Path.%v%(s,y.TrimStart('/'));g("- `{0}`",y);var aa=Path.GetDirectoryName(_);if(!%x%.Exists(aa)){%x%.CreateDirectory(aa);}using(Stream ab=x.GetStream(FileMode.Open,FileAccess.Read))using(var ac=File.OpenWrite(_)){try{ab.CopyTo(ac);}catch(FileFormatException v){g("[x]?crc: {0}",_);}}}}File.Delete(t);};%t%(var w in plist.Split(new char[]{plist.IndexOf('^|')!=-1?'^|':';'},(StringSplitOptions)1)){var ad=w.Split(new char[]{':'},2);var p=ad[0];var r=(ad.Length^>1)?ad[1]:null;var q=p.Replace('/','.');if(!String.%p%(c)){r=Path.%v%(c,r??q);}o(p,q,r);}]]^>^</Code^>^</Task^>^</%h%^>^<%h% TaskName="c" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<Task^>^<%k% %l%="%m%.Xml"/^>^<%k% %l%="%m%.Xml.Linq"/^>^<%k% %l%="WindowsBase"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.Collections.Generic"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.Linq"/^>^<%n% %o%="%m%.IO.Packaging"/^>^<%n% %o%="%m%.Xml.Linq"/^>^<%n% %o%="%m%.Text.RegularExpressions"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngin)";var b=@"$(ngout)";var c=@"$(wpath)";var d=@"$(debug)"=="true";var %_%=".nuspec";var EXT_NUPKG=".nupkg";var TAG_META="metadata";var DEF_CONTENT_TYPE="application/octet";var MANIFEST_URL="http://schemas.microsoft.com/packaging/2010/07/manifest";var ID="id";var VER="version";Action^<%r%,object^>e=%s%(%r% f,object g){if(d){%w%(f,g);}};var h=Console.Error;a=Path.%v%(c,a);if(!%x%.Exists(a)){h.%u%("`{0}` is not found.",a);%q% false;}b=Path.%v%(c,b);var i=%x%.GetFiles(a,"*"+%_%,SearchOption.TopDirectoryOnly).FirstOrDefault();if(i==null){h.%u%("{0} is not found in `{1}`",%_%,a);%q% false;}%w%("Found {0}: `{1}`",%_%,i);var j=XDocument.Load(i).Root.Elements().FirstOrDefault(k=^>k.Name.LocalName==TAG_META);if(j==null){h.%u%("{0} does not contain {1}.",i,TAG_META);%q% false;}var l=>>%bj%
<nul set /P =new Dictionary^<%r%,%r%^>();%t%(var m in j.Elements()){l[m.Name.LocalName.ToLower()]=m.Value;}if(l[ID].Length^>100^|^|!Regex.IsMatch(l[ID],@"^\w+([_.-]\w+)*$",RegexOptions.IgnoreCase^|RegexOptions.ExplicitCapture)){h.%u%("The format `{0}` is not correct.",ID);%q% false;}var n=new %r%[]{Path.%v%(a,"_rels"),Path.%v%(a,"package"),Path.%v%(a,"[Content_Types].xml")};var o=%r%.Format("{0}.{1}{2}",l[ID],l[VER],EXT_NUPKG);if(!String.IsNullOrWhiteSpace(b)){if(!%x%.Exists(b)){%x%.CreateDirectory(b);}o=Path.%v%(b,o);}%w%("Creating nupkg `{0}` ...",o);using(var p=Package.Open(o,FileMode.Create)){Uri q=new Uri(String.Format("/{0}{1}",l[ID],%_%),UriKind.Relative);p.CreateRelationship(q,TargetMode.Internal,MANIFEST_URL);%t%(var r in %x%.GetFiles(a,"*.*",SearchOption.AllDirectories)){if(n.Any(k=^>r.StartsWith(k,%z%.Ordinal))){continue;}%r% s;if(r.StartsWith(a,%z%.OrdinalIgnoreCase)){s=r.Substring(a.Length).TrimStart(Path.DirectorySeparatorChar);}else{s=r;}e("- `{0}`",s);var t=%r%.Join("/",s.Split('\\','/').Select(g=^>Uri.EscapeDataString(g)));Uri u=PackUriHelper.CreatePartUri(new Uri(t,UriKind.Relative));var v=p.CreatePart(u,DEF_CONTENT_TYPE,CompressionOption.Maximum);using(Stream w=v.GetStream())using(var x=new FileStream(r,FileMode.Open,FileAccess.Read)){x.CopyTo(w);}}Func^<%r%,%r%^>y=%s%(%r% z){%q%(l.ContainsKey(z))?l[z]:"";};var _=p.PackageProperties;_.Creator=y("authors");_.Description=y("description");_.Identifier=l[ID];_.Version=l[VER];_.Keywords=y("tags");_.Title=y("title");_.LastModifiedBy="%y% $(%y%)";}]]^>^</Code^>^</Task^>^</%h%^>^<%d% Name="Build" %e%="get"/^>^<%a%^>^<%y%^>1.8.0.7195+df76082^</%y%^>^<wpath %b%="'$(wpath)'==''"^>$(MSBuildProjectDirectory)^</wpath^>^</%a%^>^<%d% Name="header"^>^<Message Text="%%0D%%0A%y% $(%y%)%%0D%%0A(c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ] GitHub/3F%%0D%%0A" >>%bj%
<nul set /P =Importance="high"/^>^</%d%^>^</Project^>>>%bj%
exit/B 0