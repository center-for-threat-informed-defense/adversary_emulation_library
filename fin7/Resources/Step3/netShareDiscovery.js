// cscript.exe /e:jscript .\netShareDiscovery.js
// cscript.exe /b /e:jscript .\netShareDiscovery.js - /b will silence output

function netShareDiscovery(){
  var shell = WScript.CreateObject("WScript.Shell");

  try{
    var shellExecObj = shell.exec("cmd.exe /c net view /domain hospitality.local 2>&1");
    WScript.Echo(shellExecObj.StdOut.ReadAll());
  } catch(e) {
    WScript.Echo("Error: " + e);
  }

  return;
}

netShareDiscovery();
