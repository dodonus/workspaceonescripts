Add-Type -AssemblyName System.Security
function Get-CMSAuthorizationHeader
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input the URL to be
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$body,

        # Specify the Certificate to be used
        [Parameter(Mandatory=$true,
                    ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Begin
    {
        Write-Verbose -Message '[Get-CMSAuthorizationHeader] - Starting Function'
   
    }
    Process
    {
       TRY
       {
            #Get the String UTF8 encoded at first
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
            #Open Memory Stream passing the encoded bytes
            $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop
            #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
            $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop
            #Create an instance of the CMSigner class - this class object provide signing functionality
            $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop
            #Add the current time as one of the signing attribute
            $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
            #Compute the Signatur
            $SignedCMS.ComputeSignature($CMSigner)
            #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
            #One can change this value as per the format the Vendor's REST API documentation wants.
            $CMSHeader = '{0}{1}{2}' -f 'CMS','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
            Write-Output -InputObject $CMSHeader
        }
        Catch
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Get-CMSAuthorizationHeader] - Ending Function'
    }
}

function chker {
    param($value)
    if ($value -like $null) {
        $value = "-"
    } else {
        $value= $value -replace '[\\\/"\*\;\<\>\?\|\,]',"."
        $value= $value -replace '[\(\)\:]'," "
        $value= $value -replace '[][]',""
    }
  $value
}

function convertto-gb {
    param (
        $size
    ) 
    if ($null -ne $size) {
    $result=([math]::round($size/1GB,2)).tostring()}
    else {
        $result = "n/a"
    }
$result
}


function Get-CMSURLAuthorizationHeader
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input the URL to be
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [uri]$URL,

        # Specify the Certificate to be used
        [Parameter(Mandatory=$true,
                    ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Begin
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Starting Function'
  
    }
    Process
    {
       TRY
       {
            #Get the Absolute Path of the URL encoded in UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Url.AbsolutePath))

            #Open Memory Stream passing the encoded bytes
            $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop

            #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
            $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop

            #Create an instance of the CMSigner class - this class object provide signing functionality
            $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop

            #Add the current time as one of the signing attribute
            $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))

            #Compute the Signatur
            $SignedCMS.ComputeSignature($CMSigner)

            #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
            #One can change this value as per the format the Vendor's REST API documentation wants.
            $CMSHeader = '{0}{1}{2}' -f 'CMSURL','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
            Write-Output -InputObject $CMSHeader
        }
        Catch
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Ending Function'
    }
}



function params {
    param ($app, $freespace)
    #--- common ---
    $arr_of_params=[System.Collections.ArrayList]@()
    #--- common ---
    
    
    #--- ram ---    
    $mems=Get-CimInstance cim_physicalmemory | select Manufacturer, Capacity, Model, serialnumber
    $m_cntr=0
    foreach ($mem in $mems) {
        $tmp_name="ram"+$m_cntr
        $kn_manuf=$tmp_name+".Manufacturer"
        $kv_manuf=chker $mem.Manufacturer
        $null=$arr_of_params.add(@{Name=$kn_manuf;Value=$kv_manuf;ApplicationGroup=$app})
        
        $kn_cap=$tmp_name+".Capacity"
        $kv_cap=(chker (convertto-gb $mem.Capacity))+" GB"
        $null=$arr_of_params.add(@{Name=$kn_cap;Value=$kv_cap;ApplicationGroup=$app})
        
        $kn_mod=$tmp_name+".Model"
        $kv_mod=chker $mem.Model
        $null=$arr_of_params.add(@{Name=$kn_mod;Value=$kv_mod;ApplicationGroup=$app})

        $kn_sn=$tmp_name+".SerialNumber"
        $kv_sn=chker $mem.serialnumber
        $null=$arr_of_params.add(@{Name=$kn_sn;Value=$kv_sn;ApplicationGroup=$app})
        $m_cntr++
    }
    #--- ram ---
    #--- cpu ---
    $cpus=Get-CimInstance cim_processor | select Name, maxclockspeed
    
    $kn_cpu_name="CPU.Name"
    $kv_cpu_name=chker $cpus.Name
    $null=$arr_of_params.add(@{Name=$kn_cpu_name;Value=$kv_cpu_name;ApplicationGroup=$app})

    $kn_cpu_mcs="CPU.MaxClockspeed"
    $kv_cpu_mcs=chker $cpus.maxclockspeed
    $null=$arr_of_params.add(@{Name=$kn_cpu_mcs;Value=$kv_cpu_mcs;ApplicationGroup=$app})
    #--- cpu ---
    
    #--- video card ---
    $videos=Get-CimInstance cim_videocontroller | select name, CurrentHorizontalResolution, CurrentVerticalResolution, AdapterRAM
    $v_cnt=0
    foreach ($vc in $videos) {
        
        $tmp_vcname="VideoCard"+$v_cnt   
        $kn_video_name=$tmp_vcname
        $kv_video_name=chker $vc.Name
        $null=$arr_of_params.add(@{Name=$kn_video_name;Value=$kv_video_name;ApplicationGroup=$app})

        $kn_video_ram=$tmp_vcname+".RAM"
        $kv_video_ram=(chker (convertto-gb $vc.AdapterRAM))+" GB"
        $null=$arr_of_params.add(@{Name=$kn_video_ram;Value=$kv_video_ram;ApplicationGroup=$app})

        $kn_video_res=$tmp_vcname+".Resolution"
        $kv_video_res=(chker $vc.CurrentHorizontalResolution)+"x"+(chker $vc.CurrentVerticalResolution)
        $null=$arr_of_params.add(@{Name=$kn_video_res;Value=$kv_video_res;ApplicationGroup=$app})
        $v_cnt++
    }
    #--- video card ---

    #--- hd ---
    $hdrvs=Get-PhysicalDisk | select friendlyname, serialnumber, mediatype, healthstatus, size
    $hd_cnt=0
    foreach ($hd in $hdrvs) {
        $tmp_hdname="hd"+$hd_cnt
        $kn_hd_name=$tmp_hdname+".Name"
        $kv_hd_name=chker $hd.friendlyname
        $null=$arr_of_params.add(@{Name=$kn_hd_name;Value=$kv_hd_name;ApplicationGroup=$app})

        $kn_hd_sn=$tmp_hdname+".SerialNumber"
        $kv_hd_sn=chker $hd.serialnumber
        $null=$arr_of_params.add(@{Name=$kn_hd_sn;Value=$kv_hd_sn;ApplicationGroup=$app})

        $kn_hd_type=$tmp_hdname+".Type"
        $kv_hd_type=chker $hd.mediatype
        $null=$arr_of_params.add(@{Name=$kn_hd_type;Value=$kv_hd_type;ApplicationGroup=$app})

        $kn_hd_status=$tmp_hdname+".HealthStatus"
        $kv_hd_status=chker $hd.healthstatus
        $null=$arr_of_params.add(@{Name=$kn_hd_status;Value=$kv_hd_status;ApplicationGroup=$app})

        $kn_hd_size=$tmp_hdname+".size"
        $kv_hd_size= (chker (convertto-gb $hd.size))+" GB"
        $null=$arr_of_params.add(@{Name=$kn_hd_size;Value=$kv_hd_size;ApplicationGroup=$app})
        $hd_cnt++
    
    }
    if ($freespace) {
        $disks =Get-CimInstance -Class cim_logicaldisk | where {$_.drivetype -eq 3} | select deviceid, size,freespace
        foreach ($disk in $disks) {
            $disk_name = "disk "+(chker $disk.deviceid)
            $disk_info = "Total "+(chker (convertto-gb $disk.size))+" GB"+"   ---   "+"Free "+(chker (convertto-gb $disk.freespace))+" GB"
            $null=$arr_of_params.add(@{Name=$disk_name;Value=$disk_info;ApplicationGroup=$app})
        }
    }
    #--- hd ---

    #--- hostname ---
    
    $kn_hostname="hostname"
    $kv_hostname=chker $env:COMPUTERNAME
    $null=$arr_of_params.add(@{Name=$kn_hostname;Value=$kv_hostname;ApplicationGroup=$app})

    #--- hostname ---

    #--- TPM ---

    $tpm=Get-Tpm
    $kn_tpm_present = "TPM.present"
    $kv_tpm_present = chker $tpm.TpmPresent
    $null=$arr_of_params.add(@{Name=$kn_tpm_present;Value=$kv_tpm_present;ApplicationGroup=$app})
    
    $kn_tpm_ready = "TPM.ready"
    $kv_tpm_ready = chker $tpm.TpmReady
    $null=$arr_of_params.add(@{Name=$kn_tpm_ready;Value=$kv_tpm_ready;ApplicationGroup=$app})

    $kn_tpm_enabled = "TPM.enabled"
    $kv_tpm_enabled = chker $tpm.TpmEnabled
    $null=$arr_of_params.add(@{Name=$kn_tpm_enabled;Value=$kv_tpm_enabled;ApplicationGroup=$app})

    $kn_tpm_activated = "TPM.activated"
    $kv_tpm_activated = chker $tpm.TpmActivated
    $null=$arr_of_params.add(@{Name=$kn_tpm_activated;Value=$kv_tpm_activated;ApplicationGroup=$app})

    $kn_tpm_activated = "TPM.activated"
    $kv_tpm_activated = chker $tpm.TpmActivated
    $null=$arr_of_params.add(@{Name=$kn_tpm_activated;Value=$kv_tpm_activated;ApplicationGroup=$app})

    $kn_tpm_owned = "TPM.Owned"
    $kv_tpm_owned = chker $tpm.TpmOwned
    $null=$arr_of_params.add(@{Name=$kn_tpm_owned;Value=$kv_tpm_owned;ApplicationGroup=$app})

    $kn_tpm_mal = "TPM.ManagedAuthLevel"
    $kv_tpm_mal = chker $tpm.ManagedAuthLevel
    $null=$arr_of_params.add(@{Name=$kn_tpm_mal;Value=$kv_tpm_mal;ApplicationGroup=$app})

    $kn_tpm_ocd = "TPM.OwnerClearDisabled"
    $kv_tpm_ocd = chker $tpm.OwnerClearDisabled
    $null=$arr_of_params.add(@{Name=$kn_tpm_ocd;Value=$kv_tpm_ocd;ApplicationGroup=$app})

    $kn_tpm_lo = "TPM.LockedOut"
    $kv_tpm_lo = chker $tpm.LockedOut
    $null=$arr_of_params.add(@{Name=$kn_tpm_lo;Value=$kv_tpm_lo;ApplicationGroup=$app})

    $kn_tpm_ap = "TPM.AutoProvisioning"
    $kv_tpm_ap = chker $tpm.AutoProvisioning
    $null=$arr_of_params.add(@{Name=$kn_tpm_ap;Value=$kv_tpm_ap;ApplicationGroup=$app})

    $kn_tpm_loht = "TPM.LockoutHealTime"
    $kv_tpm_loht = chker $tpm.LockoutHealTime
    $null=$arr_of_params.add(@{Name=$kn_tpm_loht;Value=$kv_tpm_loht;ApplicationGroup=$app})

    $kn_tpm_loc = "TPM.LockoutCount"
    $kv_tpm_loc = chker $tpm.LockoutCount
    $null=$arr_of_params.add(@{Name=$kn_tpm_loc;Value=$kv_tpm_loc;ApplicationGroup=$app})

    $kn_tpm_lom = "TPM.LockoutMax"
    $kv_tpm_lom = chker $tpm.LockoutMax
    $null=$arr_of_params.add(@{Name=$kn_tpm_lom;Value=$kv_tpm_lom;ApplicationGroup=$app})

    #--- TPM ---

    #--- misc data ---
    $kn_date = "update time"
    $kv_date = (get-date).ToString()
    $null=$arr_of_params.add(@{Name=$kn_date;Value=$kv_date;ApplicationGroup=$app})

    $kn_osedition="OS edition"
    $kv_osediton=(Get-WindowsEdition -Online).edition
    $null=$arr_of_params.add(@{Name=$kn_osedition;Value=$kv_osediton;ApplicationGroup=$app})

    $sccm_chk_path = "c:\temp\rslt.json"
    if (Test-Path $sccm_chk_path) {
        $sccm_chk = Get-Content -Path $sccm_chk_path -Raw | ConvertFrom-Json

        $kn_sccm_crt = "SCCM certificate"
        $kv_sccm_crt = chker $sccm_chk.chk_crt
        $null=$arr_of_params.add(@{Name=$kn_sccm_crt;Value=$kv_sccm_crt;ApplicationGroup=$app})

        $kn_sccm_login = "SCCM login"
        $kv_sccm_login = chker $sccm_chk.chk_usr
        $null=$arr_of_params.add(@{Name=$kn_sccm_login;Value=$kv_sccm_login;ApplicationGroup=$app})

    } else {

        $kn_sccm_crt = "SCCM certificate"
        $kv_sccm_crt = "file is missing"
        $null=$arr_of_params.add(@{Name=$kn_sccm_crt;Value=$kv_sccm_crt;ApplicationGroup=$app})

        $kn_sccm_login = "SCCM login"
        $kv_sccm_login = "file is missing"
        $null=$arr_of_params.add(@{Name=$kn_sccm_login;Value=$kv_sccm_login;ApplicationGroup=$app})
    }
    
    

    #--- misc data ---
    

    $arr_of_params 

}

function get-awid {
    param ($udid,$kapi,$server,$crt)
    $url="https://"+$server+"/API/mdm/devices?searchBy=udid&id="+$udid


$Headers = @{
                'Authorization' = "$(Get-CMSURLAuthorizationHeader -URL $Url -Certificate $crt)";
                'aw-tenant-code' = "$kapi";
            }



    $id=(Invoke-RestMethod -Method get -Uri $url -Headers $Headers -ErrorAction Stop -ContentType "application/json;version=2" -Certificate $crt).id.value.tostring()
    $id
}

function get-awcstattrs {
    param ($id,$kapi,$server,$crt, $app)
    $url="https://"+$server+"/API/mdm/devices/customattribute/search?deviceid="+$id
    $Headers = @{
        'Authorization' = "$(Get-CMSURLAuthorizationHeader -URL $Url -Certificate $crt)";
        'aw-tenant-code' = "$kapi";
    }
    $dirty_list_attrs=(Invoke-RestMethod -Method get -Uri $url -Headers $Headers -ErrorAction Stop -ContentType "application/json;version=2" -Certificate $crt).devices.customattributes | where {$_.application -like $app} | select Name
    $result=@()
    foreach ($attr in $dirty_list_attrs) {
        $result+=@{Name=$attr.Name}
    }
    $result 
}

function remove-awattrs {
    param ($id,$kapi,$server,$crt,$app)

    $tmp=@()
    $tmp=@{CustomAttributes=(get-awcstattrs -server $server -id $id -kapi $apikey -crt $Certificate -app $app)} | ConvertTo-Json

    $url="https://$server/API/mdm/devices/$id/customattributes"

    $Headers = @{
        Authorization = "$(Get-CMSAuthorizationHeader -body $tmp -Certificate $crt)";
        'aw-tenant-code' = $apikey;
    }

    Invoke-RestMethod -Method delete -Uri $Url -Headers $Headers -ErrorAction Stop -Body $tmp -ContentType "application/json;version=2" -Certificate $crt

}

function netcheck {
    param ($apihost, $apiport)
    $pstatus=(Test-NetConnection -ComputerName $apihost -Port $apiport ).TcpTestSucceeded
    while (!($pstatus)) {
        start-sleep -s 600
        $pstatus=(Test-NetConnection -ComputerName $apihost -Port $apiport ).TcpTestSucceeded
        }
        
}


#---- var ----
$server=[serv_addr]
$thumbprint=[thimb_print]
$cpath="Cert:\LocalMachine\My\"
$apikey=[api_key]
$app="hwinvtry"
$root_path = "HKLM:\SOFTWARE\AIRWATCH\"
$enrll=$root_path+"EnrollmentStatus\"
$udid_path="HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID"
# report of free space on disk partitions
$freespace=$false

# remove custom attributes
$remattrs=$false

#---- var ----

$full_path=$cpath+$thumbprint
$Certificate = Get-ChildItem -Path $full_path

$tmp=@()
$tmp=@{CustomAttributes=params -app $app -freespace $freespace} | ConvertTo-Json

if ((Test-Path $enrll) -and ((Get-Itemproperty -Path $enrll -name status).status -like "Completed")) {

    if(Test-Path $udid_path){
        netcheck -apihost $server -apiport 443

        $udid = (Get-ItemProperty -Path $udid_path -Name "DeviceClientId").DeviceClientId
        $id=get-awid -udid $udid -kapi $apikey -server $server -crt $Certificate
        
        if($remattrs){
            remove-awattrs -app $app -crt $Certificate -id $id -kapi $apikey -server $server
        }

        $Url = "https://$server/API/mdm/devices/$id/customattributes"


        $Headers = @{
            Authorization = "$(Get-CMSAuthorizationHeader -body $tmp -Certificate $Certificate)";
            'aw-tenant-code' = $apikey;
        }

        #Invoke the awesomeness now
        Invoke-RestMethod -Method put -Uri $Url -Headers $Headers -ErrorAction Stop -Body $tmp -ContentType "application/json;version=2" -Certificate $Certificate 
     }
}
