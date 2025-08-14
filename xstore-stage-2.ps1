# --- xstore reconfiguration script ---

$scriptVer = "1.5"; # See version.md

#Objects Initialization
$global:fileBackups = @();
$global:scriptConfiguration = @();
$global:scriptErrorObject = @();

#-------------------------------------------------------------------------------------------------------------------

#Function to read in the configuration file.
Function get-ConfigFile {
        param(
                [string]$configFileLocation=(throw 'configFile is required.')
        )
        #Instantiate the script configuration variable.
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
            $global:printingIsType= (($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.type"}).Value)
            $global:printingIpAddress = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.address"}).Value
            $global:printingEpsonConfigPcsPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.epson.config.pcs.path"}).Value
            $global:printingIPJposName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.jposname"}).Value
            $global:printingIPCashJposName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.cashdrawer.jposname"}).Value
            $global:printingUSBJposName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.usb.jposname"}).Value
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
            $global:xstoreXenvBaseConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.xenvbaseconfig.path"}).Value
            $global:xstoreSystemConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.systemproperties.path"}).Value
            $global:xstorePropertiesConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.xstoreproperties.path"}).Value
            $global:xstoreMobileConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.mobile.mobileproperties.path"}).Value
            $global:xstoreMenuConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.menu.path"}).Value
            $global:xstoreDatabaseUserDtvPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.dtv.password"}).Value
            $global:xstoreDatabaseUserSaPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.sa.password"}).Value
            $global:xstoreDatabaseSqlAdminGroupNames = @(($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.sqladmin.group.names"}).Value).split(",") | ForEach-Object { $_.Trim() }
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

    if([System.Environment]::GetEnvironmentVariable('PATH', $Scope) -match [regex]::Escape($AddPath)) {
        Write-Log -type 'success' -msg "PATH variable has been set to include $AddPath in scope $Scope."
        return $true;
    }
    else {
        Write-Log -type 'error' -msg "PATH variable has not been set to include $AddPath in scope $Scope."
        write-ErrorObjectForLater -functionName "set-PathVariable" -cause "PATH variable not set correctly" -errorMessage "PATH variable has not been set to include $AddPath in scope $Scope."
        return $false;
    }
}
#Set the firewall rule to allow remote SQL access
Function set-SQLRemoteAccessFirewallRule {
    #Add the firewall rule if requested,
    New-NetFirewallRule -DisplayName "[xstore-stage-2] $global:brandName SQL Remote Access" -Direction inbound -Profile DOMAIN -Action Allow -LocalPort 1433-1434 -Protocol TCP

    #Check if the firewall rule was added.
    Start-Sleep -Seconds 15
    if(@((Get-NetFirewallRule -DisplayName *).DisplayName) -icontains "[xstore-stage-2] $global:brandName SQL Remote Access"){
        Write-Log -type 'success' -msg "Firewall rule for Remote SQL access was added (port 1433-1434, TCP) - CONFIRMED."
        return $true;
    }else{
        Write-Log -type 'error' -msg "Firewall rule not found, please add manually (port 1433-1434, TCP)."
        return $false;
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
        return $true;
    }elseif($true -eq $cannotTakeSS){
        write-ErrorObjectForLater -functionName "get-Snapshot" -cause "Cannot take snapshot" -errorMessage "A restore point has already been taken, cannot take another."
        Write-Log -type 'error' -msg "Snapshot cannot be taken, a restore point has allready been taken."
        return $false;
    }else{
        Write-Log -type 'error' -msg "The restore point has not been taken."
        write-ErrorObjectForLater -functionName "get-Snapshot" -cause "After checking the restore points we cannot find one with the correct name" -errorMessage "The restore point has not been taken."
            $snapShotContinue = Read-Host -Prompt "Do you want to continue without a restore point? (Y/N)"
            if($snapShotContinue -ilike "y*"){
                Write-Log -type 'warn' -msg "Continuing without a restore point."
                return $false;
            }else{
                Write-Log -type 'error' -msg "Cannot continue without a restore point. (exit 1)"
                return $false;
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
#Function to get the Epson Ephemeral Port from the pcs.properties file.
#This will be used to determine the ethernet port for the Epson printer.
Function update-epsonEphemeralPortConfiguration {
        #Backup current pcs.properties file
        if(invoke-ConfigFileBackup -configFileLocation $global:printingEpsonConfigPcsPath){

        write-Log -type 'general' -msg "Getting Epson Ephemeral Port from pcs.properties file."
        #Count the number of enteries in the pcs propterties file
        $pcspropxml = [xml](get-content -Path $global:printingEpsonConfigPcsPath)
        $global:numofeffport = ($pcspropxml.xmlroot.type.Value | Where-Object {$_ -ilike "ESDPRT*"}).Count

        #Get variables for later use.
        foreach($pscPort in ($pcspropxml.xmlroot.type)){
            foreach($prop in $pscPort.property | Where-Object {$_.ID -ieq "PortName"}){
                    if($prop.value -ilike "*usb*"){
                        write-log -type 'general' -msg "$($pscPort.value) is of the type USB, ($($prop.value)).";
                    }else{
                        if($prop.value -ieq '${ipprinter}'){
                            write-log -type 'general' -msg "$($pscPort.value) is of the type Ethernet, ($($prop.value)) and is configure with the OLR variable ipprinter.";
                        }else{
                                if([System.Net.IPAddress]::TryParse($prop.value, [ref]$null)){
                                    write-log -type 'general' -msg "$($pscPort.value) is of the type Ethernet and is configured with an IP address, ($($prop.value)).";
                                    if($global:printingIsIp -eq $true -or $global:printingIsIpCashDrawer -eq $true){
                                        if($global:printingIpAddress -eq $prop.value){
                                            Write-Log -type 'general' -msg " : $($global:ethernetportval) has been detected as an ethernet printer @ $($global:pcpropnetportval)."
                                        }else{
                                            Write-Log -type 'warn' -msg "The IP address configured in the pcs.properties file is not correct ($($prop.value)) This needs to be corrected."
                                            $prop.value = $global:printingIpAddress
                                            $pcspropxml.Save($global:printingEpsonConfigPcsPath)

                                            # Reload XML from disk to verify
                                            [xml]$verifyXml = Get-Content -Path $global:printingEpsonConfigPcsPath
                                            $verified = $false
                                            foreach ($pscPort in $verifyXml.xmlroot.type) {
                                                foreach ($verifyProp in $pscPort.property | Where-Object { $_.ID -ieq "PortName" }) {
                                                    if ($verifyProp.value -eq $global:printingIpAddress) {
                                                        $verified = $true
                                                        break
                                                    }
                                                }
                                                if ($verified) { break }
                                            }

                                            if ($verified) {
                                                Write-Log -type 'success' -msg "$($global:printingIpAddress) has been confirmed as the new IP address for the Epson printer in pcs.properties file."
                                                return $true;
                                            } else {
                                                Write-Log -type 'error' -msg "Failed to verify the IP address update in pcs.properties file."
                                                write-ErrorObjectForLater -functionName "get-epsonEphemeralPortConfiguration" -cause "Verification failed" -errorMessage "The IP address update could not be verified in the pcs.properties file."
                                                return $false;
                                            }
                                        }
                                    }
                                }else{
                                    Write-Log -type 'warn' -msg "$($pscPort.value) is not a valid IP address."
                                }
                        }
                    }
            }
        }
    }else{
        Write-Log -type 'error' -msg "Failed to backup config file at $global:printingEpsonConfigPcsPath."
    }
}
#Function to backup files within the same folder as the original file.
#Must feed full path to the backup file $($file.Fullname).
Function invoke-ConfigFileBackup {
           param(
            [string]$configFileLocation=(throw 'configFile is required (full name).')
        )
    #Check if the config file exists.
    if(!(Test-Path -path $configFileLocation)){
        write-ErrorObjectForLater -functionName "invoke-ConfigFileBackup" -cause "Backup target file not found." -errorMessage "The config file at $configFileLocation cannot be found, please check the path."
        Write-Log -type 'error' -msg "The config file at $configFileLocation cannot be found, please check the path. (exit 1)"
        exit 1;
    }else{
        Write-Log -type 'general' -msg "Backing up config file at $configFileLocation."

            $BackupDateTimeStamp = Get-Date -Format "dd.MM.yy-HH.mm.ss";
            $backupName = ($configFileLocation.split("\")) | Select-Object -Last 1;
            $backupPath = ($configFileLocation.split("\") | Select-Object -SkipLast 1) -join "\";
            $backupHash = (get-filehash -Path $configFileLocation -Algorithm SHA256).hash;
            $backupFileName = "$backupName.$runID.$BackupDateTimeStamp.backup";
            $backupDestenation = Join-Path -Path $backupPath -ChildPath $backupFileName;

                        $global:FileBackups += New-Object psobject -Property @{
                                Name = $backupName;
                                Path = $backupPath;
                                BackupDateTimeStamp = $BackupDateTimeStamp;
                                OriginalHash = $backupHash;
                                CopyHash = $null;
                                BackupName = $backupFileName;
                                BackupState = $null;
                                BackupLocation = $backupDestenation;
                            }

            #Backup current config file
            Copy-Item -Path $configFileLocation -Destination $backupDestenation -Force;
            $copyHash = (get-filehash -Path $backupDestenation -Algorithm SHA256).hash;

            if($copyHash -eq ($global:FileBackups | Where-Object {$_.BackupName -eq $backupFileName}).OriginalHash){
                $backupObj = $global:FileBackups | Where-Object { $_.BackupName -eq $backupFileName }
                if ($backupObj) {
                    $backupObj.CopyHash = $copyHash
                    $backupObj.BackupState = "Success";
                }
                Write-Log -type 'success' -msg "Backup file $backupFileName has been created successfully at $backupDestenation."
                return $true;
            }else{
                $backupObj = $global:FileBackups | Where-Object { $_.BackupName -eq $backupFileName }
                if ($backupObj) {
                    $backupObj.CopyHash = $copyHash
                    $backupObj.BackupState = "Failed";
                }
                write-ErrorObjectForLater -functionName "invoke-ConfigFileBackup" -cause "Backup file hash does not match original" -errorMessage "The backup file hash does not match the original file hash, please check the file integrity."
                Write-Log -type 'error' -msg "Backup file hash does not match original file hash, please check the file integrity. (exit 1)"
                return $false;
            }
        }
}
#Function to configure the IP printer in the xstore config files.
#This will modify the den.ipprinter.name and den.ipprinter.host properties in the config files.
Function invoke-ipPrinterConfiguration {
        param(
        [Parameter(Mandatory=$true)][string]$printerName,
        [Parameter(Mandatory=$true)][string]$printerIPAddress
    )
    Foreach($config in @($global:xstoreSystemConfigPath, $global:xstoreMobileConfigPath, $global:xstorePropertiesConfigPath)){
        if(!(Test-Path -path $config)){
            Write-Log -type 'warn' -msg "The config file at $config cannot be found, this may be expected depending on the config file."
        }else{
            Write-Log -type 'general' -msg "Config file at $config found, proceeding with ip printer configuration."
                if(invoke-ConfigFileBackup -configFileLocation $config){
                $lnCnt = 0;
                $tgtLn = $null;
                $propFileContent = Get-Content $config;
                    foreach($ln in $propFileContent){
                        $lnCnt ++;
                        if($ln -ilike "den.ipprinter.name*"){
                            $tgtLn = $lnCnt - 1
                            $ln = ($ln.trim() -ireplace ' ', '')
                            $currentPrinterName = ($ln.Split('=')[1]).trim();
                                Write-Log -type 'general' -msg "Currently, the ip printer name configured is '$currentPrinterName', reconfiguring to '$global:printingEpsonJposName' on line $tgtLn."
                                $ln = $ln.Replace($currentPrinterName, $printerName)
                                $propFileContent[$tgtLn] = $ln
                        }elseif($ln -ilike "den.ipprinter.host*"){
                            $tgtLn = $lnCnt - 1
                            $ln = ($ln.trim() -ireplace ' ', '')
                            $currentPrinterIp = ($ln.Split('=')[1]).trim();
                                Write-Log -type 'general' -msg "Currently, the ip printer ip address configured is '$currentPrinterIp', reconfiguring to '$printerIPAddress' on line $tgtLn."
                                $ln = $ln.Replace($currentPrinterIp, $printerIPAddress)
                                $propFileContent[$tgtLn] = $ln
                        }
                    }
                #Write the modified content back to the config file.
                Set-Content -Path $config -Value $propFileContent -Force;
            }else{
                Write-Log -type 'error' -msg "Cannot backup config file at $config, exiting."
                write-ErrorObjectForLater -functionName "invoke-ipPrinterConfiguration" -cause "Config file backup failed" -errorMessage "Cannot backup config file at $config, exiting."
                exit 1;
            }
        }
    }

}
#Parse and edit the configpath.
Function set-reconfiguredConfigPath {
    param(
        [ValidateSet('denby', 'burleigh')]
        [Parameter(Mandatory=$true)][string]$Brand,
        [ValidateSet('terminal', 'terminalip', 'terminalipcashdraw')]
        [Parameter(Mandatory=$true)][string]$hardwarePath
    )

    foreach($config in @($global:xstoreBaseConfigPath)){
        if(!(test-path -Path $config)){
            Write-Log -type 'warn' -msg "The config file at $config cannot be found, this may be expected depending on the config file."
        }else{
            Write-Log -type 'general' -msg "Config file at $config found, proceeding with reconfiguration of the config path."
            invoke-ConfigFileBackup -configFileLocation $config;
            $configPathContent = Get-Content -Path $config;
            $lnCnt = 0;
            $tgtLn = $null;
            foreach($line in $configPathContent){
                if($line -ilike "xstore.config.path.global.extensions*"){
                    $tgtLn = $lnCnt
                    write-Log -type 'general' -msg "Line $tgtLn contains the xstore.config.path.global.extensions, reconfiguring."
                    foreach($segment in ($line.Split(':'))){
                        if($segment -ilike "hardware/*"){
                            $hwSegmentOld = $segment;
                            $hwSegmentNew = "hardware", $hardwarePath -join "/";
                            Write-Log -type 'general' -msg "Line $lnCnt contains the hardware path, replacing with $hardwarePath."
                            $line = $line.Replace($hwSegmentOld, $hwSegmentNew);
                        }elseIf($segment -ilike "brand/*"){
                            $brandSegmentOld = $segment;
                            $brandSegmentNew = "brand", $Brand -join "/";
                            Write-Log -type 'general' -msg "Line $lnCnt contains the brand path, replacing with $Brand."
                            $line = $line.Replace($brandSegmentOld, $brandSegmentNew);
                        }
                    }
                }elseif($line -ilike "mobile.xstore.config.path.global.extensions*"){
                    $tgtLn = $lnCnt
                    write-Log -type 'general' -msg "Line $tgtLn contains the mobile.xstore.config.path.global.extensions, reconfiguring."
                    foreach($segment in ($line.Split(':'))){
                        if($segment -ilike "hardware/*"){
                            $hwSegmentOld = $segment;
                            $hwSegmentNew = "hardware", $hardwarePath -join "/";
                            Write-Log -type 'general' -msg "Line $lnCnt contains the hardware path, replacing with $hardwarePath."
                            $line = $line.Replace($hwSegmentOld, $hwSegmentNew);
                        }elseIf($segment -ilike "brand/*"){
                            $brandSegmentOld = $segment;
                            $brandSegmentNew = "brand", $Brand -join "/";
                            Write-Log -type 'general' -msg "Line $lnCnt contains the brand path, replacing with $Brand."
                            $line = $line.Replace($brandSegmentOld, $brandSegmentNew);
                        }
                    }
                }
            $lnCnt ++;
            }
            #Write the modified content back to the config file.
            Set-Content -Path $config -Value $configPathContent -Force;
        }
    }
}
#Function to modify config files that are key value separated by = like property files.
Function invoke-propertyFileValueChange {
            param(
    [Parameter(Mandatory=$true)][string]$configFileLocation,
    [Parameter(Mandatory=$true)][int]$changeValueTo,
    [Parameter(Mandatory=$true)][string]$lineMask
)
    if(test-path -Path $configFileLocation){
        invoke-ConfigFileBackup -configFileLocation $configFileLocation;
        write-log -type 'general' -msg "Modifying $configFileLocation to change $lineMask to $changeValueTo.";

        $configFileContent = Get-Content -Path $configFileLocation;
        $ln = 0
        foreach ($line in $configFileContent) {
            if ($line -ilike "$lineMask*") {
                $line = $line -ireplace " ", ""
                $currentStore = $line.Split('=')[1]
                $currentStore = $currentStore.Trim()
                $line = $line -ireplace "$lineMask=$currentStore", "$lineMask=$changeValueTo"
                $line = $line -ireplace "=", " = "
                $configFileContent[$ln] = $line
                $configFileContent | Set-Content -Path $configFileLocation
            }
            $ln++
        }
        
        # Sleeping to ensure writing of config file is complete. 
        Start-Sleep -Seconds 5;

        $configFileContentReRead = Get-Content -Path $configFileLocation;        
        foreach ($line in $configFileContentReRead) {
            if ($line -ilike "$lineMask*") {
                $lineReReadValue = $line;
            }
        }

        if($lineReReadValue -ilike "$lineMask = $changeValueTo"){
            Write-Log -type 'success' -msg "The $lineMask has been changed to $changeValueTo in $configFileLocation."
            return $true;
        }else{
            Write-Log -type 'error' -msg "The $lineMask was not changed to $changeValueTo in $configFileLocation on re-read of the file."
            write-ErrorObjectForLater -functionName 'invoke-propertyFileValueChange' -cause "When tested the modifications requested ($lineMask = $changeValueTo) were not actually written to the file, please check $configFileLocation manually." -errorMessage "The $lineMask was not changed to $changeValueTo in $configFileLocation on re-read of the file.";
            return $false;
        }
    }else{
            Write-Log -type 'error' -msg "$configFileLocation does not exist, exit 1."
            write-ErrorObjectForLater -functionName 'invoke-propertyFileValueChange' -cause "$configFileLocation does not seem to exist." -errorMessage "$configFileLocation does not exist, exit 1.";
            exit 1;
    }
        
}
#Function to invoke store number change.
Function invoke-storeNumberChange {
    param(
        [Parameter(Mandatory=$true)][int]$storeNumber
    )
    if($global:storeNumberChange -eq $true){
        write-log -msg general -msg "Store number change requested ($global:storeNumberChange), proceeding with store number change to $storeNumber."
        #Make the store number changes in the configuration files.
        invoke-propertyFileValueChange -configFileLocation $global:xstoreBaseConfigPath -changeValueTo $storeNumber -lineMask 'dtv.location.StoreNumber'
        invoke-propertyFileValueChange -configFileLocation $global:xstoreXenvBaseConfigPath -changeValueTo $storeNumber -lineMask 'installx.rtlLocId'

        #Correction to store number change by OLR
        write-Log -type 'general' -msg "Changing store number using ClientData.sql file to $storeNumber, log output is at $global:scriptLoggingPath\$runid-SQLChangeStoreNumberOutput.log."
        Start-Process 'sqlcmd' -ArgumentList "-S localhost -U dtv -P $global:xstoreDatabaseUserDtvPassword -v OrgID=1 StoreID=$storeNumber CountryID='GB' CurrencyID='GBP' -i C:\xstore\database\ClientData.sql -o $global:scriptLoggingPath\$runid-SQLChangeStoreNumberOutput.log";
    }else{
        Write-Log -type 'warn' -msg "Store number change not requested ($global:storeNumberChange), no changes have been made."
    }
}
#Function to invoke park retail ID change based on xml file. 
function invoke-pridChange {
    param(
        [Parameter(Mandatory=$true)][int]$storeNumber
    )

    if($global:parkRetailchange -eq $true){
        $pridmap = [xml](get-content -Path $global:parkRetailMap); 
        $correctMap = $pridmap.prids.store | Where-Object {$_.storenum -ieq $storeNumber};

        if($null -eq $correctMap -or $correctMap -eq ''){
            Write-Log -type 'warn' -msg "Correct map for new store number $newStoreNum cannot be found in $global:parkRetailMap, check data is correct, no changes have been made."
        }else{
            foreach($ociusPropFile in (Get-ChildItem -Path $global:pedsEftlinkPath -Recurse | Where-Object {$_.Name -ilike 'ocius.properties'})){
                invoke-propertyFileValueChange -configFileLocation $ociusPropFile.FullName -changeValueTo $correctMap.storeprid -lineMask 'flexecash.account.id'
            }
        }
    }else{
        Write-Log -type 'warn' -msg "Park retail change not requested ($global:parkRetailchange), no changes have been made."
    }
}
#Function to add default scheduled tasks.
Function invoke-addDefaultSchedTasks {
   
# Task Definitions
$defaultSchedTasks = @(
    @{
        Name = "$global:brandName-WindowsUpdateController"
        Desc = 'Will run a script that will update Windows if the host name is in a shared txt file on the sdrive.'
        Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -File "auto-windows-update-v20.ps1"' -WorkingDirectory "C:\$global:brandName\Scripts\"
        Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Tuesday -At 9:30PM
        Condition = { $true } # Always run
    },
    @{
        Name = "$global:brandName-XstoreDatabaseBackup"
        Desc = 'Will run a script that will backup the store database to head office.'
        Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -File "backup-xstore-db.ps1"' -WorkingDirectory "C:\$global:brandName\Scripts"
        Trigger = New-ScheduledTaskTrigger -Daily -At ("{0:D2}:{1:D2}" -f (Get-Random -Minimum 2 -Maximum 4), (Get-Random -Minimum 1 -Maximum 59))
        Condition = { Test-Path "C:\$brand\Scripts\backup-xstore-db.ps1" }
    },
    @{
        Name = "$global:brandName-XstoreRestart"
        Desc = 'Will run a script that will restart the xstore system.'
        Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -File "xstore-shutdown-restart.ps1"' -WorkingDirectory "C:\$global:brandName\Scripts"
        Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Monday -At 6am
        Condition = { $true }
    },
    @{
        Name = "$global:brandName-LaunchXstoreAtLogon"
        Desc = 'This will launch xStore at logon of any user using the VBS file C:\environment\start_eng.vbs.'
        Action = New-ScheduledTaskAction -Execute 'Cscript.exe' -Argument 'C:\environment\start_eng.vbs //nologo' -WorkingDirectory 'C:\Windows\System32'
        Trigger = New-ScheduledTaskTrigger -AtLogOn
        Condition = { $true }
    },
    @{
        Name = "$global:brandName-ScriptUpdater"
        Desc = "This script will update all other scripts within the $brand scripts folder."
        Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -File "xStore-ScriptUpdater.ps1"' -WorkingDirectory "C:\$brand"
        Trigger = New-ScheduledTaskTrigger -Daily -At 7am
        Condition = { $true }
    }
)

    # Register all tasks
    foreach ($task in $defaultSchedTasks){
        if(& $task.Condition){
            Write-Log -type 'General' -msg "Adding task [$($task.Name)]"
            Register-ScheduledTask -Action $task.Action -Trigger $task.Trigger -TaskName $task.Name -Description $task.Desc -TaskPath "$global:brandName" -RunLevel Highest -Force
        }else{
            Write-Log -type 'warn' -msg "Skipping task [$($task.Name)] due to condition not met."
        }
    }

    # Verify tasks
    Start-Sleep -Seconds 5
    foreach ($task in $defaultSchedTasks) {
        if ((Get-ScheduledTask -TaskName *).TaskName -icontains $task.Name) {
            Write-Log -type 'success' -msg "$($task.Name) successfully added."
        }
        else {
            Write-Log -type 'error' -msg "$($task.Name) was not added."
            write-ErrorObjectForLater -functionName 'invoke-addDefaultSchedTasks' -cause "When the script tried to confim that the task was added to the system the task could not be found. Please check $($task.Name) manually." -errorMessage "$($task.Name) was not added.";
        }
    }
}
#Add configured groups to local database db administrators
Function invoke-denbyDBAdminToLocalDBRemoteUsers {
    If(((Get-Process | Where-Object {$_.Name -ilike "*sqlserv*"}).count) -gt 0){
        Foreach($dbName in $global:xstoreDatabaseSqlAdminGroupNames){

# SQL commands to add the user to the SQL server and database roles.
$xstoreAdminActionsSql = @"
    USE [master]
    GO
    CREATE LOGIN [$dbName] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
    GO
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$dbName]
    GO
    USE [xstore]
    GO
    CREATE USER [$dbName] FOR LOGIN [$dbName]
    GO
    USE [xstore]
    GO
    ALTER ROLE [db_owner] ADD MEMBER [$dbName]
    GO
"@;

# Get list of database admins allready in the database.
$adminTestSql = @"
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

                    if(((Invoke-Sqlcmd -U 'sa' -P $global:xstoreDatabaseUserSaPassword -Query $adminTestSql).login) -icontains $dbName){
                        Write-Log -msg 'warn' -msg "SQL server allready contains $dbName, doing nothing."
                    }else{
                        Write-Log -msg 'info' -msg "Detected SQL server running, adding $dbName to remote users."
                        Invoke-Sqlcmd -U 'sa' -P $global:xstoreDatabaseUserSaPassword -Query $xstoreAdminActionsSql | out-null
                        Start-Sleep -Seconds 20
                            if(((Invoke-Sqlcmd -U 'sa' -P $global:xstoreDatabaseUserSaPassword -Query $adminTestSql).login) -icontains $dbName){
                                Write-Log -msg 'success' -msg "Confirming that $dbName has been added to the users that can logon remotely."
                                return $true;
                            }else{
                                Write-Log -msg 'error' -msg "$dbName has not been added to the database."
                                return $false;
                            }
                    }
            }
    }else{
        Write-Log -type 'error' -msg "Cannot detect running SQL server, server process count is $sqlServerRunningCnt."
        return $false;
    }
}
#Function to invoke PED IP Change. 
Function invoke-pedIpChange {
    if($global:amountOfPeds -gt '0' -and $global:changePedsConfiguration -eq $true){

        foreach($ociusPropFile in 1..$global:amountOfPeds){
            $ociusPropFilePath = "$global:pedsEftlinkPath\server$ociusPropFile\ocius.properties"
            $correctPedIpAddress = $(Get-Variable -Name ("pedsIpAddress"+$ociusPropFile) -ValueOnly)
            if([System.Net.IPAddress]::TryParse($correctPedIpAddress, [ref]$null)){
                invoke-propertyFileValueChange -configFileLocation $ociusPropFilePath -changeValueTo $correctPedIpAddress -lineMask 'ip.address'
            }else{
                write-log -type 'error' -msg "$correctPedIpAddress does not seem to be an IP addess.";
                write-ErrorObjectForLater -functionName 'invoke-pedIpChange' -cause "Configured ped Ip of $(Get-Variable -Name ("pedsIpAddress"+$ociusPropFile) -ValueOnly) does not appear to be an acutal IP. Check the config file." -errorMessage "$correctPedIpAddress does not seem to be an IP addess";
            }
        }

    }else{
        Write-Log -type 'warn' -msg "There are ($global:amountOfPeds) peds in this store, no configuration is required or Ped change is not configured ($global:changePedsConfiguration)."
    }
}

#Read in the script config file.
Get-ConfigFile -configFileLocation ".\.env";
#This is for file naming for the logs.
$logFileDate = (get-date -Format "dd.MM.yy-HH.mm.ss");
#Generate a random id to track a single run of the script.
$runID = (-join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_}));
#this is for the run time calulation
$startTime = (get-date -Format "HH:mm:ss");

#-------------------------------------------------------------------------------------------------------------------

Write-Log -type "general" -msg " ------------- (RUNID: $runID Ver:$scriptVer) Start run at $(get-date -format "dd.MM.yy - HH:mm:ss") running on $env:computername ------------- "

Set-PathVariable -AddPath "C:\Program Files\Java\jdk-$global:xstoreRequiredJdkVersion\bin" -Scope Machine;
Set-SQLRemoteAccessFirewallRule;
invoke-AutoLogon;
invoke-storeNumberChange;
invoke-pridChange;
invoke-denbyDBAdminToLocalDBRemoteUsers;
invoke-pedIpChange;

if($global:changePrintingConfiguration -eq $true){
    #Set the reconfigured config path.
    switch ($global:printingIsType) {
        'usb' { set-reconfiguredConfigPath -Brand $global:brandName -hardwarePath "terminal"; }
        'ip' { set-reconfiguredConfigPath -Brand $global:brandName -hardwarePath "terminalip"; invoke-ipPrinterConfiguration -printerName $global:printingIPJposName -printerIPAddress $global:printingIpAddress ; update-epsonEphemeralPortConfiguration;}
        'ipcashdrawer' { set-reconfiguredConfigPath -Brand $global:brandName -hardwarePath "terminalipcashdrawer"; invoke-ipPrinterConfiguration -printerName $global:printingIPCashJposName -printerIPAddress $global:printingIpAddress ; update-epsonEphemeralPortConfiguration;}
    }
}

invoke-xStoreConfigurationBats;
invoke-addDefaultSchedTasks;

write-log -type 'general' -msg "File Backups Commited During Script Execution:"
$global:fileBackups | Format-Table -AutoSize | out-file $global:scriptLoggingPath -append;
write-log -type 'general' -msg "This Runs Configuration Was:"
$global:scriptConfiguration | Format-Table -AutoSize | out-file $global:scriptLoggingPath -append;
write-log -type 'general' -msg "Errors During Operation Were:"
$global:scriptErrorObject | Format-Table -AutoSize | out-file $global:scriptLoggingPath -append;

write-log -type 'general' -msg "Process has finished, the script took $((New-TimeSpan -Start $startTime -End $((get-date -Format "HH:mm:ss"))).Minutes) minutes and $((New-TimeSpan -Start $startTime -End $endTime).Seconds) seconds.";
Write-Log -type "general" -msg " ------------- (RUNID: $runID Ver:$scriptVer) End run at $(get-date -format "dd.MM.yy - HH:mm:ss") running on $env:computername ------------- "

"Disposing of all Variables for next run"
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0;

exit 0;