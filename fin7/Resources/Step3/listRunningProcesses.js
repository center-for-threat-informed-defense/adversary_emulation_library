// wscript.exe /e:jscript .\listRunningProcesses.js
// wscript.exe /b /e:jscript .\listRunningProcesses.js - /b will silence output

function listRunningProcesses(){
  var root = GetObject("winmgmts:");
  var processes = root.ExecQuery("Select * From Win32_Process");
  var processes_list = [];

  for (var items = new Enumerator(processes); !items.atEnd(); items.moveNext()) {
    var item = items.item();
    processes_list.push(item.caption);
  }

  return(processes_list);
}

WScript.Echo(listRunningProcesses());
