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
            $global:brandChange = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "brand.change"}).Value;
            $global:brandName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "brand.name"}).Value;
        #Store Number Configuration Variables.
            $global:storeNumberChange = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "store.number.change"}).Value;
            $global:storeNumberNew = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "store.number.new"}).Value;
        #Park Retail Configuration Variables.
            $global:parkRetailChange = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "park.retail.change"}).Value;
            $global:parkRetailMap = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "park.retail.map.path"}).Value;
        #Automatic Windows Logon Configuration Variables.
            $global:enableWindowsAutoLogon = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "auto.logon"}).Value;
            $global:automaticWindowsLogonPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "auto.logon.password"}).Value;
        #Printing Configuration
            $global:changePrintingConfiguration = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.change"}).Value;
            $global:printingIsIp = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.ip"}).Value;
            $global:printingIsIpCashDrawer = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.ipcashdrawer"}).Value;
            $global:printingIsUsb = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.usb"}).Value;
            $global:printingIsXStoreShared = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.is.xstoreShared"}).Value;
            $global:printingIpAddress = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.address"}).Value;
            $global:printingIpCashDrawerAddress = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.ip.cashdrawer.address"}).Value;
            $global:printingUsbSharedHostname = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.usbshared.hostname"}).Value;
            $global:printingEpsonConfigPcsPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "printer.epson.config.pcs.path"}).Value;
        #Peds Configuration
            $global:changePedsConfiguration = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.change"}).Value;
            $global:amountOfPeds = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.amount"}).Value;
            $global:pedsIpAddress1 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.1"}).Value;
            $global:pedsIpAddress2 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.2"}).Value;
            $global:pedsIpAddress3 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.3"}).Value;
            $global:pedsIpAddress4 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.4"}).Value;
            $global:pedsIpAddress5 = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.ip.address.5"}).Value;
            $global:pedsEftlinkPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "peds.eftlink.path"}).Value;
        #XStore Configuration Variables.
            $global:xstoreBaseConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.baseproperties.path"}).Value;
            $global:xstoreSystemConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.systemproperties.path"}).Value;
            $global:xstoreMobileConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.mobile.mobileproperties.path"}).Value;
            $global:xstoreMenuConfigPath = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.menu.path"}).Value;
            $global:xstoreDatabaseUserDtvPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.dtv.password"}).Value;
            $global:xstoreDatabaseUserSaPassword = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.user.sa.password"}).Value;
            $global:xstoreDatabaseSqlAdminGroupName = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.sqladmin.group.name"}).Value;
            $global:xstoreDatabaseSqlAdminDomain = ($global:scriptConfiguration | Where-Object {$_.Property -ieq "xstore.config.database.sqladmin.domain"}).Value;
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
        $global:logFile = "$($scriptConfiguration.Value)\$runID-xstore-stage2-$($logFileDate).log"

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
