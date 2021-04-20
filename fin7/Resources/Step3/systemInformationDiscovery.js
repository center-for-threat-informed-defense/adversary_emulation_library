// wscript.exe /e:jscript .\systemInformationDiscovery.js
// wscript.exe /b /e:jscript .\systemInformationDiscovery.js - /b will silence output


// Set globals to be used in functions
var root = GetObject("winmgmts:");
var shell = WScript.CreateObject("WScript.Shell");

function is_vm(){
  var biosRequest = root.ExecQuery("Select * From Win32_BIOS");
  var biosItems = new Enumerator(biosRequest);

  for (; !biosItems.atEnd(); biosItems.moveNext()){
    var bios_version = biosItems.item().SMBIOSBIOSVersion.toLowerCase();
    var serial_number = biosItems.item().SerialNumber.toLowerCase();
    if(serial_number.indexOf('parallels') >= 0 || serial_number.indexOf('vmware') >= 0) {
      return true;
    }

    if(bios_version.indexOf('vmware') >= 0 || bios_version.indexOf('virtualbox') >= 0) {
      return true;
    }
  }

  return false;
}

function get_active_directory_information(){
  try {
    var adobj = new ActiveXObject('ADSystemInfo');
    return adobj.ComputerName;
  } catch(e) {
    return false;
  }
}

function get_env_var(name){
  return shell.ExpandEnvironmentStrings(name);
}

function get_system_information(){
  var result = [];
  try{
    result.push('username***' + get_env_var('%USERNAME%'));
    result.push('hostname***' + get_env_var('%COMPUTERNAME%'));
    var ad = get_active_directory_information();
    if(ad){
      result.push('adinformation***' + ad);
    } else {
      result.push('adinformation***no_ad');
    }

    var csRequest = root.ExecQuery('Select * From Win32_ComputerSystem');
    var csItems = new Enumerator(csRequest);

    for(; !csItems.atEnd(); csItems.moveNext()) {
      if(csItems.item().PartOfDomain){
        result.push('part_of_domain***yes');
      } else {
        result.push('part_of_domain***no');
      }
      result.push('pc_domain***' + csItems.item().Domain);
      result.push('pc_dns_host_name***' + csItems.item().DNSHostName);
      result.push('pc_model***' + csItems.item().Model);
    }
  } catch (e){
    result.push('error0***code_error');
  }

  try{
    var osRequest = root.ExecQuery('Select * From Win32_OperatingSystem');
    var osItems = new Enumerator(osRequest);

    for(; !osItems.atEnd(); osItems.moveNext()) {
      if(osItems.item().OSArchitecture){
        result.push('os_architecture***' + osItems.item().OSArchitecture);
      }

      if(osItems.item().Version){
        result.push('os_version***' + osItems.item().Version);
      }
    }

  } catch (e){
    result.push('error1***code_error');
  }

  return(result);
}

// Main
WScript.Echo("is_vm: " + is_vm());
WScript.Echo(get_system_information());
