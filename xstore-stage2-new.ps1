# --- xstore reconfiguration script ---

$scriptVer = "0.1"; # See version.md

#-------------------------------------------------------------------------------------------------------------------

#Function to read in the configuration file.
Function get-ConfigFile {
        param(
                [string]$configFileLocation=(throw 'configFile is required.')
        )
        
        #Instantiate the script configuration variable.
        $global:scriptConfiguration = @();
                if(Test-Path -path $configFileLocation){
                #Read the config file and add to the configuration variable.
                foreach ($config in (Get-Content $configFileLocation | Where-Object {$_ -notlike "#*" -and $_ -match "="})) {
                        $global:scriptConfiguration += New-Object psobject -Property @{
                            Property = $config.Split("=")[0].Trim();
                            Value = $config.Split("=")[1].Trim();
                        }
                    }
        }else{
                write-host "ERROR: Config file cannot be found at $configFileLocation " -BackgroundColor DarkGray -ForegroundColor Red
        }

        #Declare Configuration Variables.
        #Script Configuration Variables.
            $global:scriptLoggingPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "script.logging.path"}).Value;
        #Brand Configuration Variables.
            $global:brandChange = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "brand.change"}).Value -eq "true")
            $global:brandName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "brand.name"}).Value
        #Store Number Configuration Variables.
            $global:storeNumberChange = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "store.number.change"}).Value -eq "true")
            $global:storeNumberNew = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "store.number.new"}).Value
        #Park Retail Configuration Variables.
            $global:parkRetailChange = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "park.retail.change"}).Value -eq "true")
            $global:parkRetailMap = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "park.retail.map.path"}).Value
        #Automatic Windows Logon Configuration Variables.
            $global:enableWindowsAutoLogon = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "auto.logon"}).Value -eq "true")
            $global:automaticWindowsLogonPassword = ConvertTo-SecureString -String $(($global:scriptConfiguration | Where-Object {$_.Property -ieq "auto.logon.password"}).Value) -AsPlainText -Force
        #Printing Configuration
            $global:changePrintingConfiguration = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.change"}).Value -eq "true")
            $global:printingIsIp = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.ip"}).Value -eq "true")
            $global:printingIsIpCashDrawer = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.ipcashdrawer"}).Value -eq "true")
            $global:printingIsUsb = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.usb"}).Value -eq "true")
            $global:printingIsXStoreShared = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.xstoreShared"}).Value -eq "true")
            $global:printingIpAddress = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.address"}).Value
            $global:printingIpCashDrawerAddress = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.cashdrawer.address"}).Value
            $global:printingUsbSharedHostname = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.usbshared.hostname"}).Value
            $global:printingEpsonConfigPcsPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.epson.config.pcs.path"}).Value
        #Peds Configuration
            $global:changePedsConfiguration = (($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.change"}).Value -eq "true")
            $global:amountOfPeds = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.amount"}).Value
            $global:pedsIpAddress1 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.1"}).Value
            $global:pedsIpAddress2 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.2"}).Value
            $global:pedsIpAddress3 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.3"}).Value
            $global:pedsIpAddress4 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.4"}).Value
            $global:pedsIpAddress5 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.5"}).Value
            $global:pedsEftlinkPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.eftlink.path"}).Value
        #XStore Configuration Variables.
            $global:xstoreBaseConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.baseproperties.path"}).Value
            $global:xstoreSystemConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.systemproperties.path"}).Value
            $global:xstoreMobileConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.mobile.mobileproperties.path"}).Value
            $global:xstoreMenuConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.menu.path"}).Value
            $global:xstoreDatabaseUserDtvPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.dtv.password"}).Value
            $global:xstoreDatabaseUserSaPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.sa.password"}).Value
            $global:xstoreDatabaseSqlAdminGroupName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.sqladmin.group.name"}).Value
            $global:xstoreDatabaseSqlAdminDomain = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.sqladmin.domain"}).Value
            $global:xstoreRequiredJdkVersion = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.required.jdk.version"}).Value;
}
#Function to write to the log file.
Function write-Log {
        param(
            [Parameter(Mandatory=$true)][String]$msg,
            [Parameter(Mandatory=$true)][String]$type
        )

        # Get time of log action.
        $global:logtime = get-date -Format "dd.MM.yy-HH.mm.ss"
        $global:logFile = "$($global:scriptLoggingPath)\$runID-xstore-stage2-$($logFileDate).log"

        # Write to correct logging file.
        if($type -ilike "error"){
                write-host $logtime '-' '[' $type ']' '-' $msg -ForegroundColor DarkRed -BackgroundColor red
                Add-Content -Path $logFile -Value "$logtime - [$type] - $msg"
        }elseif($type -ilike "warn"){
                write-host $logtime '-' '[' $type ']' '-' $msg -ForegroundColor DarkYellow -BackgroundColor yellow
                Add-Content -Path $logFile -Value "$logtime - [$type] - $msg"
        }elseif($type -ilike "success"){
                write-host $logtime '-' '[' $type ']' '-' $msg -ForegroundColor DarkGreen -BackgroundColor green
                Add-Content -Path $logFile -Value "$logtime - [$type] - $msg"
        }elseif($type -ilike "general"){
                write-host $logtime '-' '[' $type ']' '-' $msg -ForegroundColor black -BackgroundColor white
                Add-Content -Path $logFile -Value "$logtime - [$type] - $msg"
        }elseif($type -ilike "debug"){
                write-host $logtime '-' '[' $type ']' '-' $msg -ForegroundColor DarkBlue -BackgroundColor blue
                Add-Content -Path $logFile -Value "$logtime - [-------- $type --------] - $msg"
        }else{
                write-host "Warning: Log type not defined correctly, options are error, warn, good, debug, general or general." -ForegroundColor DarkYellow -BackgroundColor yellow
                write-host "FYI: logging path set to $logFile." -ForegroundColor black -BackgroundColor white
        }
}
#Function to set the PATH variable, used for adding the JDK to the PATH.
Function set-PathVariable {
    param (
        [string]$AddPath,
        [string]$RemovePath,
        [ValidateSet('Process', 'User', 'Machine')]
        [string]$Scope
        )

    $regexPaths = @()
    if ($PSBoundParameters.Keys -contains 'AddPath') {
        $regexPaths += [regex]::Escape($AddPath)
    }

    if ($PSBoundParameters.Keys -contains 'RemovePath') {
        $regexPaths += [regex]::Escape($RemovePath)
    }
    
    $arrPath = [System.Environment]::GetEnvironmentVariable('PATH', $Scope) -split ';'
    foreach ($path in $regexPaths) {
        $arrPath = $arrPath | Where-Object { $_ -notMatch "^$path\\?" }
    }

    $value = ($arrPath + $addPath) -join ';'
    if($debug -eq $true){
        Write-Log -type "debug" -msg "Setting PATH variable to: $value"
    }else{
        Write-Log -type "general" -msg "Adding $AddPath to PATH variable in scope $Scope."
    }
    # Set the PATH variable in the specified scope.
    [System.Environment]::SetEnvironmentVariable('PATH', $value, $Scope)
}
#Set the firewall rule to allow remote SQL access
Function set-SQLRemoteAccessFirewallRule {
    #Add the firewall rule if requested,
    New-NetFirewallRule -DisplayName "[xstore-stage-2] $global:brandName SQL Remote Access" -Direction inbound -Profile DOMAIN -Action Allow -LocalPort 1433-1434 -Protocol TCP

    #Check if the firewall rule was added.
    Start-Sleep -Seconds 15
    if(@((Get-NetFirewallRule -DisplayName *).DisplayName) -icontains "[xstore-stage-2] $global:brandName SQL Remote Access"){
        Write-Log -type 'success' -msg "Firewall rule for Remote SQL access was added (port 1433-1434, TCP) - CONFIRMED."
    }else{
        Write-Log -type 'error' -msg "Firewall rule not found, please add manually (port 1433-1434, TCP)."
    }
}
#Take a restore point prior to modification
Function get-Snapshot {
$takendate = @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}
$lastTakenDate = (Get-ComputerRestorePoint | Select-Object -Property $takendate, SequenceNumber, Description  -last 1 | Sort-Object -Property SequenceNumber -Descending).Date
$ssDateStamp = Get-Date -Format "dd.MM.yy-HH.mm.ss"

if($null -eq $lastTakenDate){

    write-log -type 'warn' -msg "Cannot get date of last system restore point, attempting to take one."
    Checkpoint-Computer -Description "[xstore-stage-2] $brand-before-stage2-$ssDateStamp" -RestorePointType "MODIFY_SETTINGS"
    Start-Sleep -Seconds 45

}elseif($lastTakenDate -gt (Get-Date).AddDays(-1)){

    write-log -type 'warn' -msg "A Restore point has already been taken in the last 24 hours, cannot take another (last taken $lastTakenDate)."
    $cannotTakeSS = $true

}else{

    Write-Log -type 'general' -msg "Generating Windows System Restore point."
    Checkpoint-Computer -Description "[xstore-stage-2] $brand-before-stage2-$ssDateStamp" -RestorePointType "MODIFY_SETTINGS"
    Start-Sleep -Seconds 45
}

    #Check status of system restore point.
    Write-Log -type 'general' -msg "Last restore point status - $(Get-ComputerRestorePoint -LastStatus)"

    #Check if the restore point was taken.
    if(@((Get-ComputerRestorePoint).Description) -icontains "[xstore-stage-2] $brand-before-stage2-$ssDateStamp"){
        Write-Log -type 'success' -msg "A restore point has been taken before making any changes."
    }elseif($true -eq $cannotTakeSS){
        write-ErrorObjectForLater -functionName "get-Snapshot" -cause "Cannot take snapshot" -errorMessage "A restore point has already been taken, cannot take another."
        Write-Log -type 'error' -msg "Snapshot cannot be taken, a restore point has allready been taken."
    }else{
        Write-Log -type 'error' -msg "The restore point has not been taken."
        write-ErrorObjectForLater -functionName "get-Snapshot" -cause "After checking the restore points we cannot find one with the correct name" -errorMessage "The restore point has not been taken."
            $snapShotContinue = Read-Host -Prompt "Do you want to continue without a restore point? (Y/N)"
            if($snapShotContinue -ilike "Y"){
                Write-Log -type 'warn' -msg "Continuing without a restore point."
            }else{
                Write-Log -type 'error' -msg "Cannot continue without a restore point, exiting script."
                exit 1
            }
    }
}
#Function to create an error object for later use.
Function write-ErrorObjectForLater {
    param(
        [Parameter(Mandatory=$true)][string]$functionName,
        [Parameter(Mandatory=$true)][string]$cause,
        [Parameter(Mandatory=$true)][string]$errorMessage
    )
    
    # Add the error object to the global error object array.
    $global:scriptErrorObject += New-Object psobject -Property @{
        FunctionName = $functionName;
        Cause = $cause;
        ErrorMessage = $errorMessage;
        timestamp = (Get-Date -Format "dd.MM.yy-HH.mm.ss");
        }

        Write-Log -type "error" -msg "Adding error for later - $functionName - $cause - $errorMessage"

}
#Runs xstore / xenviroment configuration bat files. 
Function invoke-xStoreConfigurationBats {
    $configBatNames = @("baseconfigure.bat","configure.bat","mobile_baseconfigure.bat","mobile_configure.bat");
    $ConfigBatPaths = @("c:\xstore", "c:\xstore-mobile", "c:\xenvironment");
    Get-ChildItem -path $ConfigBatPaths -Include $configBatNames | foreach-object {
            Write-Log " : $($_.FullName) has been found, running."
            Start-Process "cmd.exe" -ArgumentList "/c $($_.FullName)" -Wait
            Start-Sleep -Seconds 5
    }

}
#Function to enable Windows Auto Logon.
Function invoke-AutoLogon {
    if($global:enableWindowsAutoLogon -eq $false){
        Write-Log -type 'general' -msg "Automatic windows logon was not requested ($global:enableWindowsAutoLogon), skipping."
    }elseif($global:enableWindowsAutoLogon -eq $true){
        #Get the domain name and convert to upper case.
        $domain = (((Get-CIMInstance CIM_ComputerSystem).domain).split('.')[0]).ToUpper();
        Write-Log -type 'general' -msg "Using the following for auto logon, username: $domain\$env:USERNAME password: $(ConvertFrom-SecureString -SecureString $global:automaticWindowsLogonPassword -AsPlainText)."

        #write the values
        $autoLogonRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty $autoLogonRegPath 'AutoAdminLogon' -Value "1" -Type String -Force
            Set-ItemProperty $autoLogonRegPath 'DefaultUsername' -Value "\$env:USERNAME" -type String -Force
            Set-ItemProperty $autoLogonRegPath 'DefaultPassword' -Value $global:automaticWindowsLogonPassword -type String -Force
            Remove-ItemProperty $autoLogonRegPath 'AutoLogonCount' -ErrorAction SilentlyContinue;
            if(Test-Path -path "C:\$global:brandName\Autologon64.exe"){
                try{
                    #attempting to set up autologn with autologon64.exe
                    Start-Process -FilePath "C:\$global:brandName\Autologon64.exe" -ArgumentList "/accepteula", $env:USERNAME, $domain, $(ConvertFrom-SecureString -SecureString $global:automaticWindowsLogonPassword -AsPlainText) -wait;
                }catch{
                    write-ErrorObjectForLater -functionName "invoke-AutoLogon" -cause "Autologon64.exe failed to run" -errorMessage "Autologon64.exe failed to run, please check the path and the arguments (error: $($error[0].Exception.Message))"
                }
            }else{
                write-ErrorObjectForLater -functionName "invoke-AutoLogon" -cause "Autologon64.exe not found" -errorMessage "Cannot find Autologon64.exe in C:\$global:brandName\Autologon64.exe, please check the path."
            }
    }
}
#Add users to db administrators
Function add-dbAdminToLocalDBRemoteUsers {

$denbySQLAdminsGroup = @($global:xstoreDatabaseSqlAdminDomain, $global:xstoreDatabaseSqlAdminGroupName) -join "\";
$addDenbySQLAdmins = @"
    USE [master]
    GO
    CREATE LOGIN [$denbySQLAdminsGroup] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
    GO
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$denbySQLAdminsGroup]
    GO
    USE [xstore]
    GO
    CREATE USER [$denbySQLAdminsGroup] FOR LOGIN [$denbySQLAdminsGroup]
    GO
    USE [xstore]
    GO
    ALTER ROLE [db_owner] ADD MEMBER [$denbySQLAdminsGroup]
    GO
"@
$checkDenbySQLAdmins = @"
select sp.name as login,
       sp.type_desc as login_type,
       case when sp.is_disabled = 1 then 'Disabled'
            else 'Enabled' end as status
from sys.server_principals sp
left join sys.sql_logins sl
          on sp.principal_id = sl.principal_id
where sp.type not in ('R','C')
order by sp.name;
"@

    If(((Get-Process | Where-Object {$_.Name -ilike "*sqlserv*"}).count) -gt '0'){
            if((@(Invoke-Sqlcmd -U $dbAdminUserName -P $dbAdminUserPass -Query $checkDenbySQLAdmins).login) -icontains $denbySQLAdminsGroup){
                Write-Log -type 'warn' -msg "SQL server allready contains $denbySQLAdminsGroup, no action has been taken."
            }else{
                    Invoke-Sqlcmd -U 'sa' -P $global:xstoreDatabaseUserSaPassword -Query $addDenbySQLAdmins | out-null
                    Start-Sleep -Seconds 20
                            if(@((Invoke-Sqlcmd -U 'sa' -P $global:xstoreDatabaseUserSaPassword -Query $checkDenbySQLAdmins).login) -icontains $denbySQLAdminsGroup){
                                Write-Log -type 'success' -msg "Confirming that $global:xstoreDatabaseSqlAdminGroupName has been added to the users that can logon remotely."
                            }else{
                                Write-Log -type 'error' -msg "$denbySQLAdminsGroup has not been added to the database."
                                write-ErrorObjectForLater -functionName "add-dbAdminToLocalDBRemoteUsers" -cause "SQL admin group not added" -errorMessage "$denbySQLAdminsGroup has not been added to the database, please check the SQL server is running and the credentials are correct."
                            }
            }
    }else{
        Write-Log -type 'error' -msg "Cannot detect running SQL server."
        write-ErrorObjectForLater -functionName "add-dbAdminToLocalDBRemoteUsers" -cause "Cannot detect running SQL server" -errorMessage "Cannot detect running SQL server, therefor unable to add $denbySQLAdminsGroup to the database."
    }
}

#Read in the script config file.
Get-ConfigFile -configFileLocation ".\.env";
#This is for file naming for the logs.
$logFileDate = (get-date -Format "dd.MM.yy-HH.mm.ss");
#this is for the run time calulation
$startTime = (get-date -Format "HH:mm:ss");
#Generate a random id to track a single run of the script.
$runID = (-join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_}));

$global:scriptErrorObject = @();

#-------------------------------------------------------------------------------------------------------------------

Set-PathVariable -AddPath "C:\Program Files\Java\jdk-$global:xstoreRequiredJdkVersion\bin" -Scope Machine;
Set-SQLRemoteAccessFirewallRule;
invoke-xStoreConfigurationBats;
invoke-AutoLogon;
