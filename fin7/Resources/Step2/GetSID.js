// wscript.exe /e:jscript .\GetSID.js
// wscript.exe /b /e:jscript .\GetSID.js - /b will silence output

function GetSID(){
  var root = GetObject("winmgmts:");
  var mac = root.ExecQuery("Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True");
  var mac_address = "",
      serial = "";
  
  for (var items = new Enumerator(mac); !items.atEnd(); items.moveNext()) {
    var item = items.item();
    if (typeof item.MACAddress == "string"){
      mac_address = item.MACAddress.replace(/:/g, '');
      break;
    }
  }

  var lc = root.ExecQuery("Select * from Win32_LogicalDisk");
  for (var items = new Enumerator(lc); !items.atEnd(); items.moveNext()) {
    var item = items.item();
    if (typeof item.VolumeSerialNumber == "string"){
      serial = item.VolumeSerialNumber;
      break;
    }
  }

  var ret = mac_address + serial;
  ret = ret.substr(0, 21);
  return(ret);
}

WScript.Echo(GetSID());
