@echo off
:: Copyright (c) 2016-2021  Denis Kuzmin [x-3F@outlook.com] github/3F
:: https://github.com/3F/DllExport
if "%~1"=="/?" goto bq
set "aa=%~dpnx0"
set ab=%*
set ac=%*
if defined ab (
if defined __p_call (
set ac=%ac:^^=^%
) else (
set ab=%ab:^=^^%
)
)
set wMgrArgs=%ac%
set ad=%ab:!=^!%
setlocal enableDelayedExpansion
set "ae=^"
set "ad=!ad:%%=%%%%!"
set "ad=!ad:&=%%ae%%&!"
set "af=1.7.4"
set "wAction=Configure"
set "ag=DllExport"
set "ah=tools/net.r_eg.DllExport.Wizard.targets"
set "ai=packages"
set "aj=https://www.nuget.org/api/v2/package/"
set "ak=build_info.txt"
set "al=!aa!"
set "wRootPath=!cd!"
set /a wDxpOpt=0
set "am="
set "an="
set "ao="
set "ap="
set "aq="
set "ar="
set "as="
set "at="
set "au="
set "av="
set /a aw=0
if not defined ab (
if defined wAction goto br
goto bq
)
call :bs bk !ad! bl
goto bt
:bq
echo.
@echo .NET DllExport v1.7.4.29858+c1cc52f
@echo Copyright (c) 2009-2015  Robert Giesecke
@echo Copyright (c) 2016-2021  Denis Kuzmin ^<x-3F@outlook.com^> github/3F
echo.
echo MIT License
@echo https://github.com/3F/DllExport
echo Based on hMSBuild, MvsSln, +GetNuTool: https://github.com/3F
echo.
@echo.
@echo Usage: DllExport [args to DllExport] [args to GetNuTool] [args to hMSBuild]
echo ------
echo.
echo Arguments
echo ---------
echo -action {type} - Specified action for Wizard. Where {type}:
echo   * Configure - To configure DllExport for specific projects.
echo   * Update    - To update pkg reference for already configured projects.
echo   * Restore   - To restore configured DllExport.
echo   * Export    - To export configured projects data.
echo   * Recover   - To re-configure projects via predefined/exported data.
echo   * Unset     - To unset all data from specified projects.
echo   * Upgrade   - Aggregates an Update action with additions for upgrading.
echo.
echo -sln-dir {path}    - Path to directory with .sln files to be processed.
echo -sln-file {path}   - Optional predefined .sln file to be processed.
echo -metalib {path}    - Relative path to meta library.
echo -metacor {path}    - Relative path to meta core library.
echo -dxp-target {path} - Relative path to entrypoint wrapper of the main core.
echo -dxp-version {num} - Specific version of DllExport. Where {num}:
echo   * Versions: 1.7.3 ...
echo   * Keywords:
echo     `actual` - Unspecified local/latest remote version;
echo                ( Only if you know what you are doing )
echo.
echo -msb {path}           - Full path to specific msbuild.
echo -hMSBuild {args}      - Access to hMSBuild tool (packed) https://github.com/3F/hMSBuild
echo -packages {path}      - A common directory for packages.
echo -server {url}         - Url for searching remote packages.
echo -proxy {cfg}          - To use proxy. The format: [usr[:pwd]@]host[:port]
echo -pkg-link {uri}       - Direct link to package from the source via specified URI.
echo -force                - Aggressive behavior, e.g. like removing pkg when updating.
echo -no-mgr               - Do not use %~nx0 for automatic restore the remote package.
echo -mgr-up               - Updates %~nx0 to version from '-dxp-version'.
echo -wz-target {path}     - Relative path to entrypoint wrapper of the main wizard.
echo -pe-exp-list {module} - To list all available exports from PE32/PE32+ module.
echo -eng                  - Try to use english language for all build messages.
echo -GetNuTool {args}     - Access to GetNuTool (integrated) https://github.com/3F/GetNuTool
echo -debug                - To show additional information.
echo -version              - Displays version for which (together with) it was compiled.
echo -build-info           - Displays actual build information from selected DllExport.
echo -help                 - Displays this help. Aliases: -help -h
echo.
echo Flags
echo -----
echo  __p_call - To use the call-type logic when invoking %~nx0
echo.
echo Samples
echo -------
echo DllExport -action Configure -force -pkg-link http://host/v1.7.3.nupkg
echo DllExport -action Restore -sln-file "Conari.sln"
echo DllExport -proxy guest:1234@10.0.2.15:7428 -action Configure
echo.
echo DllExport -mgr-up -dxp-version 1.7.3
echo DllExport -action Upgrade -dxp-version 1.7.3
echo.
echo DllExport -GetNuTool /p:ngpackages="Conari;regXwild"
echo DllExport -pe-exp-list bin\Debug\regXwild.dll
goto bu
:bt
set /a ax=0
:bv
set ay=!bk[%ax%]!
if [!ay!]==[-help] ( goto bq ) else if [!ay!]==[-h] ( goto bq ) else if [!ay!]==[-?] ( goto bq )
if [!ay!]==[-debug] (
set am=1
goto bw
) else if [!ay!]==[-action] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wAction=!v!
for %%g in (Restore, Configure, Update, Export, Recover, Unset, Upgrade, Default) do (
if "!v!"=="%%g" goto bw
)
echo Unknown -action !v!
exit/B 1
) else if [!ay!]==[-sln-dir] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wSlnDir=!v!
goto bw
) else if [!ay!]==[-sln-file] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wSlnFile=!v!
goto bw
) else if [!ay!]==[-metalib] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wMetaLib=!v!
goto bw
) else if [!ay!]==[-metacor] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wMetaCor=!v!
goto bw
) else if [!ay!]==[-dxp-target] ( set /a "ax+=1" & call :bx bk[!ax!] v
set wDxpTarget=!v!
goto bw
) else if [!ay!]==[-dxp-version] ( set /a "ax+=1" & call :bx bk[!ax!] v
set af=!v!
goto bw
) else if [!ay!]==[-msb] ( set /a "ax+=1" & call :bx bk[!ax!] v
set ao=!v!
goto bw
) else if [!ay!]==[-packages] ( set /a "ax+=1" & call :bx bk[!ax!] v
set ai=!v!
goto bw
) else if [!ay!]==[-server] ( set /a "ax+=1" & call :bx bk[!ax!] v
set aj=!v!
goto bw
) else if [!ay!]==[-proxy] ( set /a "ax+=1" & call :bx bk[!ax!] v
set at=!v!
set wProxy=!v!
goto bw
) else if [!ay!]==[-pkg-link] ( set /a "ax+=1" & call :bx bk[!ax!] v
set ap=!v!
set af=!ay!
goto bw
) else if [!ay!]==[-force] (
set ar=1
goto bw
) else if [!ay!]==[-no-mgr] (
set /a wDxpOpt^|=1
goto bw
) else if [!ay!]==[-mgr-up] (
set as=1
goto bw
) else if [!ay!]==[-wz-target] ( set /a "ax+=1" & call :bx bk[!ax!] v
set ah=!v!
goto bw
) else if [!ay!]==[-pe-exp-list] ( set /a "ax+=1" & call :bx bk[!ax!] v
set aq=!v!
goto bw
) else if [!ay!]==[-eng] (
chcp 437 >nul
goto bw
) else if [!ay!]==[-GetNuTool] (
call :by -GetNuTool 10
set /a aw=!ERRORLEVEL! & goto bu
) else if [!ay!]==[-hMSBuild] (
set av=1 & goto br
) else if [!ay!]==[-version] (
@echo v1.7.4.29858+c1cc52f  %__dxp_pv%
goto bu
) else if [!ay!]==[-build-info] (
set an=1
goto bw
) else if [!ay!]==[-tests] ( set /a "ax+=1" & call :bx bk[!ax!] v
set au=!v!
goto bw
) else (
echo Incorrect key: !ay!
set /a aw=1
goto bu
)
:bw
set /a "ax+=1" & if %ax% LSS !bl! goto bv
:br
call :bz "dxpName = " ag
call :bz "dxpVersion = " af
call :bz "-sln-dir = " wSlnDir
call :bz "-sln-file = " wSlnFile
call :bz "-metalib = " wMetaLib
call :bz "-metacor = " wMetaCor
call :bz "-dxp-target = " wDxpTarget
call :bz "-wz-target = " ah
call :bz "#opt " wDxpOpt
if defined af (
if "!af!"=="actual" (
set "af="
)
)
set wPkgVer=!af!
if z%wAction%==zUpgrade (
call :bz "Upgrade is on"
set as=1
set ar=1
)
call :b0 ai
set "ai=!ai!\\"
set "az=!ag!"
set "wPkgPath=!ai!!ag!"
if defined af (
set "az=!az!/!af!"
set "wPkgPath=!wPkgPath!.!af!"
)
if defined ar (
if exist "!wPkgPath!" (
call :bz "Removing old version before continue. '-force' key rule. " wPkgPath
rmdir /S/Q "!wPkgPath!"
)
)
set a0="!wPkgPath!\\!ah!"
call :bz "wPkgPath = " wPkgPath
if not exist !a0! (
if exist "!wPkgPath!" (
call :bz "Trying to replace obsolete version ... " wPkgPath
rmdir /S/Q "!wPkgPath!"
)
call :bz "-pkg-link = " ap
call :bz "-server = " aj
if defined ap (
set aj=!ap!
if "!aj::=!"=="!aj!" (
set aj=!cd!/!aj!
)
if "!wPkgPath::=!"=="!wPkgPath!" (
set "a1=../"
)
set "az=:!a1!!wPkgPath!|"
)
if defined ao (
set a2=-msbuild "!ao!"
)
set a3=!a2! /p:ngserver="!aj!" /p:ngpackages="!az!" /p:ngpath="!ai!" /p:proxycfg="!at! "
call :bz "GetNuTool call: " a3
if defined am (
call :b1 !a3!
) else (
call :b1 !a3! >nul
)
)
if defined av (
call :by -hMSBuild 9
set /a aw=!ERRORLEVEL! & goto bu
)
if defined aq (
"!wPkgPath!\\tools\\PeViewer.exe" -list -pemodule "!aq!"
set /a aw=%ERRORLEVEL%
goto bu
)
if defined an (
call :bz "buildInfo = " wPkgPath ak
if not exist "!wPkgPath!\\!ak!" (
echo information about build is not available.
set /a aw=2
goto bu
)
type "!wPkgPath!\\!ak!"
goto bu
)
if not exist !a0! (
echo Something went wrong. Try to use another keys.
set /a aw=2
goto bu
)
call :bz "wRootPath = " wRootPath
call :bz "wAction = " wAction
call :bz "wMgrArgs = " wMgrArgs
if defined ao (
call :bz "Use specific MSBuild tools: " ao
set a4="!ao!"
goto b2
)
call :b3 bm & set a4="!bm!"
if "!ERRORLEVEL!"=="0" goto b2
echo MSBuild tools was not found. Try with `-msb` key.
set /a aw=2
goto bu
:b2
if not defined a4 (
echo Something went wrong. Use `-debug` key for details.
set /a aw=2
goto bu
)
if not defined au (
if not defined ao if defined wPkgPath (
set a4="!wPkgPath!\\hMSBuild"
for /f "tokens=*" %%i in ('!a4! -version') do set a5=%%i
call :b4 !a5! bn
call :bz "hMSBuild -v" a5 bn
if !bn! GEQ 230 (
call :bz "2.3+"
set a4=!a4! -vsw-as "-requiresAny -requires Microsoft.NetCore.Component.SDK Microsoft.Net.Core.Component.SDK -products * -latest -prerelease"
)
)
call :bz "Target: " a4 a0
call !a4! /nologo /v:m /m:4 !a0!
)
:bu
if defined au (
echo Running Tests ... "!au!"
call :b3 bo
"!bo!" /nologo /v:m /m:4 "!au!"
exit/B 0
)
if defined as (
(copy /B/Y "!wPkgPath!\\DllExport.bat" "!al!" > nul) && ( echo Manager has been updated. & exit/B 0 ) || ( (echo -mgr-up failed:!aw! 1>&2) & exit/B 1 )
)
exit/B !aw!
:b4
set a6=%~1
for /f "tokens=1,2 delims=." %%a in ("!a6!") do (
set _=%%b & set /a _*=10 & set /a %2=%%a!_!
)
exit/B 0
:by
set ay=%~1
set /a a7=%~2
call :bz "accessing to !ay! ..."
for /L %%p IN (0,1,8181) DO (
if "!ad:~%%p,%a7%!"=="!ay!" (
set a8=!ad:~%%p!
set a9=!a8:~%a7%!
if defined av (
call "!wPkgPath!\\hMSBuild" !a9!
) else (
call :b1 !a9!
)
exit/B !ERRORLEVEL!
)
)
call :bz "!ay! is corrupted: " ad
exit/B 1
:b3
call :bz "Searching from .NET Framework - .NET 4.0, ..."
for %%v in (4.0, 3.5, 2.0) do (
call :b5 %%v Y & if defined Y (
set %1=!Y!
exit/B 0
)
)
call :bz "msb -netfx: not found"
set "%1="
exit/B 2
:b5
call :bz "check %1"
for /F "usebackq tokens=2* skip=2" %%a in (
`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSBuild\ToolsVersions\%1" /v MSBuildToolsPath 2^> nul`
) do if exist %%b (
set a_=%%~b
call :bz ":msbfound " a_
call :b6 a_ bp
set %2=!bp!
exit/B 0
)
set "%2="
exit/B 0
:b6
set %2=!%~1!\MSBuild.exe
exit/B 0
:bz
if defined am (
set ba=%1
set ba=!ba:~0,-1!
set ba=!ba:~1!
echo.[%TIME% ] !ba! !%2! !%3!
)
exit/B 0
:b0
call :b7 %1
call :b8 %1
exit/B 0
:b7
call :b9 %1 "-=1"
exit/B 0
:b8
call :b9 %1 "+=1"
exit/B 0
:b9
set bb=z!%1!z
if "%~2"=="-=1" (set "bc=1") else (set "bc=")
if defined bc (
set /a "i=-2"
) else (
set /a "i=1"
)
:b_
if "!bb:~%i%,1!"==" " (
set /a "i%~2"
goto b_
)
if defined bc set /a "i+=1"
if defined bc (
set "%1=!bb:~1,%i%!"
) else (
set "%1=!bb:~%i%,-1!"
)
exit/B 0
:bs
set "bd=%~1"
set /a ax=-1
:ca
set /a ax+=1
set %bd%[!ax!]=%~2
shift & if not "%~3"=="" goto ca
set /a ax-=1
set %1=!ax!
exit/B 0
:bx
set %2=!%1!
exit/B 0
:b1
setlocal disableDelayedExpansion
@echo off
:: GetNuTool - Executable version
:: Copyright (c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ]
:: https://github.com/3F/GetNuTool
set be=gnt.core
set bf="%temp%\%random%%random%%be%"
if "%~1"=="-unpack" goto cb
set bg=%*
if defined __p_call if defined bg set bg=%bg:^^=^%
set bh=%__p_msb%
if defined bh goto cc
if "%~1"=="-msbuild" goto cd
for %%v in (4.0, 14.0, 12.0, 3.5, 2.0) do (
for /F "usebackq tokens=2* skip=2" %%a in (
`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSBuild\ToolsVersions\%%v" /v MSBuildToolsPath 2^> nul`
) do if exist %%b (
set bh="%%~b\MSBuild.exe"
goto cc
)
)
echo MSBuild was not found. Try -msbuild "fullpath" args 1>&2
exit/B 2
:cd
shift
set bh=%1
shift
set bi=%bg:!= #__b_ECL## %
setlocal enableDelayedExpansion
set bi=!bi:%%=%%%%!
:ce
for /F "tokens=1* delims==" %%a in ("!bi!") do (
if "%%~b"=="" (
call :cf !bi!
exit/B %ERRORLEVEL%
)
set bi=%%a #__b_EQ## %%b
)
goto ce
:cf
shift & shift
set "bg="
:cg
set bg=!bg! %1
shift & if not "%~2"=="" goto cg
set bg=!bg: #__b_EQ## ==!
setlocal disableDelayedExpansion
set bg=%bg: #__b_ECL## =!%
:cc
call :ch
call %bh% %bf% /nologo /p:wpath="%cd%/" /v:m /m:4 %bg%
set "bh="
set bj=%ERRORLEVEL%
del /Q/F %bf%
exit/B %bj%
:cb
set bf="%cd%\%be%"
echo Generating minified version in %bf% ...
:ch
<nul set /P ="">%bf%
set a=PropertyGroup&set b=Condition&set c=ngpackages&set d=Target&set e=DependsOnTargets&set f=TaskCoreDllPath&set g=MSBuildToolsPath&set h=UsingTask&set i=CodeTaskFactory&set j=ParameterGroup&set k=Reference&set l=Include&set m=System&set n=Using&set o=Namespace&set p=IsNullOrEmpty&set q=return&set r=string&set s=delegate&set t=foreach&set u=WriteLine&set v=Combine&set w=Console.WriteLine&set x=Directory&set y=GetNuTool&set z=StringComparison&set _=EXT_NUSPEC
<nul set /P =^<!-- GetNuTool - github.com/3F/GetNuTool --^>^<!-- Copyright (c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ] --^>^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>^<%a%^>^<ngconfig %b%="'$(ngconfig)'==''"^>packages.config^</ngconfig^>^<ngserver %b%="'$(ngserver)'==''"^>https://www.nuget.org/api/v2/package/^</ngserver^>^<%c% %b%="'$(%c%)'==''"^>^</%c%^>^<ngpath %b%="'$(ngpath)'==''"^>packages^</ngpath^>^</%a%^>^<%d% Name="get" BeforeTargets="Build" %e%="header"^>^<a^>^<Output PropertyName="plist" TaskParameter="Result"/^>^</a^>^<b plist="$(plist)"/^>^</%d%^>^<%d% Name="pack" %e%="header"^>^<c/^>^</%d%^>^<%a%^>^<%f% %b%="Exists('$(%g%)\Microsoft.Build.Tasks.v$(MSBuildToolsVersion).dll')"^>$(%g%)\Microsoft.Build.Tasks.v$(MSBuildToolsVersion).dll^</%f%^>^<%f% %b%="'$(%f%)'=='' and Exists('$(%g%)\Microsoft.Build.Tasks.Core.dll')"^>$(%g%)\Microsoft.Build.Tasks.Core.dll^</%f%^>^</%a%^>^<%h% TaskName="a" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<%j%^>^<Result Output="true"/^>^</%j%^>^<Task^>^<%k% %l%="%m%.Xml"/^>^<%k% %l%="%m%.Xml.Linq"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.Collections.Generic"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.Xml.Linq"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngconfig)";var b=@"$(%c%)";var c=@"$(wpath)";if(!String.%p%(b)){Result=b;%q% true;}var d=Console.Error;Action^<%r%,Queue^<%r%^>^>e=%s%(%r% f,Queue^<%r%^>g){%t%(var h in XDocument.Load(f).Descendants("package")){var i=h.Attribute("id");var j=h.Attribute("version");var k=h.Attribute("output");if(i==null){d.%u%("'id' does not exist in '{0}'",f);%q%;}var l=i.Value;if(j!=null){l+="/"+j.Value;}if(k!=null){g.Enqueue(l+":"+k.Value);continue;}g.Enqueue(l);}};var m=new Queue^<%r%^>();%t%(var f in a.Split(new char[]{a.IndexOf('^|')!=-1?'^|':';'},(StringSplitOptions)1))>>%bf%
<nul set /P ={var n=Path.%v%(c,f);if(File.Exists(n)){e(n,m);}else{d.%u%(".config '{0}' is not found.",n);}}if(m.Count^<1){d.%u%("Empty list. Use .config or /p:%c%\n");}else{Result=%r%.Join("|",m.ToArray());}]]^>^</Code^>^</Task^>^</%h%^>^<%h% TaskName="b" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<%j%^>^<plist/^>^</%j%^>^<Task^>^<%k% %l%="WindowsBase"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.IO.Packaging"/^>^<%n% %o%="%m%.Net"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngserver)";var b=@"$(wpath)";var c=@"$(ngpath)";var d=@"$(proxycfg)".Trim();var e=@"$(debug)"=="true";if(plist==null){%q% false;}ServicePointManager.SecurityProtocol^|=SecurityProtocolType.Tls11^|SecurityProtocolType.Tls12;var f=new %r%[]{"/_rels/","/package/","/[Content_Types].xml"};Action^<%r%,object^>g=%s%(%r% h,object i){if(e){%w%(h,i);}};Func^<%r%,WebProxy^>j=%s%(%r% k){var l=k.Split('@');if(l.Length^<=1){%q% new WebProxy(l[0],false);}var m=l[0].Split(':');%q% new WebProxy(l[1],false){Credentials=new NetworkCredential(m[0],(m.Length^>1)?m[1]:null)};};Func^<%r%,%r%^>n=%s%(%r% i){%q% Path.%v%(b,i??"");};Action^<%r%,%r%,%r%^>o=%s%(%r% p,%r% q,%r% r){var s=Path.GetFullPath(n(r??q));if(%x%.Exists(s)){%w%("`{0}` was found in \"{1}\"",q,s);%q%;}Console.Write("Getting `{0}` ... ",p);var t=Path.%v%(Path.GetTempPath(),Guid.NewGuid().ToString());using(var u=new WebClient()){try{if(!String.%p%(d)){u.Proxy=j(d);}u.Headers.Add("User-Agent","%y% $(%y%)");u.UseDefaultCredentials=true;if(u.Proxy.Credentials==null){u.Proxy.Credentials=CredentialCache.DefaultCredentials;}u.DownloadFile(a+p,t);}catch(Exception v){Console.Error.%u%(v.Message);%q%;}}%w%("Extracting into \"{0}\"",s);using(var w=ZipPackage.Open(t,FileMode.Open,FileAccess.Read)){%t%(var x in w.GetParts()){var y=Uri.UnescapeDataString(x.Uri.OriginalString);if>>%bf%
<nul set /P =(f.Any(z=^>y.StartsWith(z,%z%.Ordinal))){continue;}var _=Path.%v%(s,y.TrimStart('/'));g("- `{0}`",y);var aa=Path.GetDirectoryName(_);if(!%x%.Exists(aa)){%x%.CreateDirectory(aa);}using(Stream ab=x.GetStream(FileMode.Open,FileAccess.Read))using(var ac=File.OpenWrite(_)){try{ab.CopyTo(ac);}catch(FileFormatException v){g("[x]?crc: {0}",_);}}}}File.Delete(t);};%t%(var w in plist.Split(new char[]{plist.IndexOf('^|')!=-1?'^|':';'},(StringSplitOptions)1)){var ad=w.Split(new char[]{':'},2);var p=ad[0];var r=(ad.Length^>1)?ad[1]:null;var q=p.Replace('/','.');if(!String.%p%(c)){r=Path.%v%(c,r??q);}o(p,q,r);}]]^>^</Code^>^</Task^>^</%h%^>^<%h% TaskName="c" TaskFactory="%i%" AssemblyFile="$(%f%)"^>^<Task^>^<%k% %l%="%m%.Xml"/^>^<%k% %l%="%m%.Xml.Linq"/^>^<%k% %l%="WindowsBase"/^>^<%n% %o%="%m%"/^>^<%n% %o%="%m%.Collections.Generic"/^>^<%n% %o%="%m%.IO"/^>^<%n% %o%="%m%.Linq"/^>^<%n% %o%="%m%.IO.Packaging"/^>^<%n% %o%="%m%.Xml.Linq"/^>^<%n% %o%="%m%.Text.RegularExpressions"/^>^<Code Type="Fragment" Language="cs"^>^<![CDATA[var a=@"$(ngin)";var b=@"$(ngout)";var c=@"$(wpath)";var d=@"$(debug)"=="true";var %_%=".nuspec";var EXT_NUPKG=".nupkg";var TAG_META="metadata";var DEF_CONTENT_TYPE="application/octet";var MANIFEST_URL="http://schemas.microsoft.com/packaging/2010/07/manifest";var ID="id";var VER="version";Action^<%r%,object^>e=%s%(%r% f,object g){if(d){%w%(f,g);}};var h=Console.Error;a=Path.%v%(c,a);if(!%x%.Exists(a)){h.%u%("`{0}` is not found.",a);%q% false;}b=Path.%v%(c,b);var i=%x%.GetFiles(a,"*"+%_%,SearchOption.TopDirectoryOnly).FirstOrDefault();if(i==null){h.%u%("{0} is not found in `{1}`",%_%,a);%q% false;}%w%("Found {0}: `{1}`",%_%,i);var j=XDocument.Load(i).Root.Elements().FirstOrDefault(k=^>k.Name.LocalName==TAG_META);if(j==null){h.%u%("{0} does not contain {1}.",i,TAG_META);%q% false;}var l=>>%bf%
<nul set /P =new Dictionary^<%r%,%r%^>();%t%(var m in j.Elements()){l[m.Name.LocalName.ToLower()]=m.Value;}if(l[ID].Length^>100^|^|!Regex.IsMatch(l[ID],@"^\w+([_.-]\w+)*$",RegexOptions.IgnoreCase^|RegexOptions.ExplicitCapture)){h.%u%("The format `{0}` is not correct.",ID);%q% false;}var n=new %r%[]{Path.%v%(a,"_rels"),Path.%v%(a,"package"),Path.%v%(a,"[Content_Types].xml")};var o=%r%.Format("{0}.{1}{2}",l[ID],l[VER],EXT_NUPKG);if(!String.IsNullOrWhiteSpace(b)){if(!%x%.Exists(b)){%x%.CreateDirectory(b);}o=Path.%v%(b,o);}%w%("Creating nupkg `{0}` ...",o);using(var p=Package.Open(o,FileMode.Create)){Uri q=new Uri(String.Format("/{0}{1}",l[ID],%_%),UriKind.Relative);p.CreateRelationship(q,TargetMode.Internal,MANIFEST_URL);%t%(var r in %x%.GetFiles(a,"*.*",SearchOption.AllDirectories)){if(n.Any(k=^>r.StartsWith(k,%z%.Ordinal))){continue;}%r% s;if(r.StartsWith(a,%z%.OrdinalIgnoreCase)){s=r.Substring(a.Length).TrimStart(Path.DirectorySeparatorChar);}else{s=r;}e("- `{0}`",s);var t=%r%.Join("/",s.Split('\\','/').Select(g=^>Uri.EscapeDataString(g)));Uri u=PackUriHelper.CreatePartUri(new Uri(t,UriKind.Relative));var v=p.CreatePart(u,DEF_CONTENT_TYPE,CompressionOption.Maximum);using(Stream w=v.GetStream())using(var x=new FileStream(r,FileMode.Open,FileAccess.Read)){x.CopyTo(w);}}Func^<%r%,%r%^>y=%s%(%r% z){%q%(l.ContainsKey(z))?l[z]:"";};var _=p.PackageProperties;_.Creator=y("authors");_.Description=y("description");_.Identifier=l[ID];_.Version=l[VER];_.Keywords=y("tags");_.Title=y("title");_.LastModifiedBy="%y% $(%y%)";}]]^>^</Code^>^</Task^>^</%h%^>^<%d% Name="Build" %e%="get"/^>^<%a%^>^<%y%^>1.8.0.43837+df76082^</%y%^>^<wpath %b%="'$(wpath)'==''"^>$(MSBuildProjectDirectory)^</wpath^>^</%a%^>^<%d% Name="header"^>^<Message Text="%%0D%%0A%y% $(%y%)%%0D%%0A(c) 2015-2018,2020  Denis Kuzmin [ x-3F@outlook.com ] GitHub/3F%%0D%%0A" >>%bf%
<nul set /P =Importance="high"/^>^</%d%^>^</Project^>>>%bf%
exit/B 0