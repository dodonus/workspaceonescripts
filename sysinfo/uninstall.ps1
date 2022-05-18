Unregister-ScheduledTask -TaskPath "\trgt\" -TaskName "sysinfo" -Confirm:$false 
Remove-ItemProperty -path "HKLM:\SOFTWARE\AWFLGS" -name "sysinfo_v" 
Remove-Item -path "$env:ProgramData\AirwatchMDM\AppDeploymentCache\trgt\sysinfo.ps1"
