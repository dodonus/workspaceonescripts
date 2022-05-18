powershell.exe -executionpolicy bypass -file uninstall.ps1
$trg_dir = "$env:ProgramData\AirwatchMDM\AppDeploymentCache\trgt"
if (!(Test-Path $trg_dir)) {
    New-Item -Path $trg_dir -ItemType directory
}


Copy-Item .\sysinfo.ps1 -Destination $trg_dir -Force
if(!((Get-ScheduledTask -taskname sysinfo).taskpath -like "\trgt\")){
schtasks /create /RU "SYSTEM" /SC ONSTART /TN trgt\sysinfo /TR "powershell -executionpolicy bypass -file %programdata%\AirWatchMDM\AppDeploymentCache\trgt\sysinfo.ps1"
}

if (!(Test-Path -Path HKLM:\SOFTWARE\AWFLGS) {
    new-item -Path HKLM:\SOFTWARE\AWFLGS
}
New-ItemProperty -path "HKLM:\SOFTWARE\AWFLGS" -name "sysinfo_v" -Value "8.5"

