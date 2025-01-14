#v1.03 130624 --- Added configuration for cashdraws connected to IP printer kick ports.
#v1.03 110423 --- Cleaned Up Schedualed Tasks.
#v1.02 210323 --- Updated logging function.
#v1.01 100323 --- Add receipt email address change for BLL.
#v1.00 080223 --- Code review and clean up, build to pilot.
#v0.19 070223 --- Modified configpath modification to only edit the base-xstore file.
#v0.19 070223 --- Added editing config path to modify brand.
#v0.18 100123 --- Added update ocius.keystore option at Cathys request.
#v0.17 121122 --- Fix PCS.properties IP address editing.
#v0.16 --- Cleanup and fix auto-logon.
#v0.15 --- Externalising more configuration variables, including DB Passwords. 
#v0.14 --- Updated with correction for store number change from OLR.
#v0.13 --- Updated config path change to support xstore mobile config path.
#v0.13 --- Updated config path change to edit base xstore file so it does not overwrite changed values.
#v0.12 --- Implemented Park Retail configuration modification at Peters Request.
#v0.11 --- Correct Printer Sharing client configuration so it also edits v1 jpos.xml.
#v0.10 --- Handle creating correct ethernet port configuration in PCS.prop if none is present.
#v0.09 --- Implement changing of ip printer address in PCS.properties.
#v0.08 --- Implement Logical Port number reading and updating in jpos.
#v0.07 --- Implemented the rest of schedualed tasks.
#v0.06 --- Implemented adding denby sql admin group to local database.
#v0.06 --- Implement Auto logon, new IP printer mechanism, start of implementing schedualed tasks.
#v0.05 --- Implement store number change.
#v0.04 --- Implement changing config path to specifiy which config is used.
#v0.03 --- Clean up and add jdk to path.
#v0.02 --- Add Ip recipt printer configuration.
#v0.01 --- Add functions to read and write content from jar files
#v0.00 --- Initial build.

#Go to correct directory when run as admin
Set-Location $PSScriptRoot -Verbose

#Generating run ID for multiple run logging.
$runid = get-date -format "HH-mm-ss"

#xstore stage 2 updater
$s2configpath = ".\.env";
$s2config = [xml](Get-Content $s2configpath);
$logDIR = ".\logs";
$loggingpath = "$logDIR\v20-stage-2-log-RUNID_$runid.txt";

#Printing Config
#---- Program Config
$hwconfigpath = $s2config.TillConfig.Program.hwconfigjarpath;
$eftlinkdir = $s2config.TillConfig.Program.eftlinkdir;
$autoclosexstore = $s2config.TillConfig.Program.autoclosexstore;
$pcsproppath = $s2config.TillConfig.Program.pcsproploc;
$sqlfwreq = $s2config.TillConfig.Program.addsqlremoteaccess;
$xstoresysprop = $s2config.TillConfig.Program.xstoresysproperties;
$xstoresyspropmob = $s2config.TillConfig.Program.xstoresyspropertiesMOB;
$dvtdbuserpass = $s2config.TillConfig.Program.dvtuserpass;
$sadbuserpass = $s2config.TillConfig.Program.sauserpass;
$jdkver = $s2config.TillConfig.Program.jdkver;
$updateOcKs = $s2config.TillConfig.Program.updateOciusKeystore;
$brand = $s2config.TillConfig.Program.brand;
#---- Store Number Config
$changestnum = $s2config.TillConfig.storenumber.changestorenum;
$newstorenum = $s2config.TillConfig.storenumber.newstorenumis;
$xstorebaseconfigloc = $s2config.TillConfig.Program.xstorebaseconf;
$xenvironbaseconfigloc = $s2config.TillConfig.Program.xenvirobaseconf;
#---- Peter Requests
$pridcnreq = $s2config.TillConfig.peterrequests.pridchange;
$pridmaploc = $s2config.TillConfig.peterrequests.pridmaploc;
#---- Auto Logon Config
$enableautologon = $s2config.TillConfig.autologon.enableautologon;
$autologonpass = $s2config.TillConfig.autologon.userpass;
#---- server config
$isprintserver = $s2config.TillConfig.printing.PSisprintserver;
$fwreq = $s2config.TillConfig.printing.createsharefwrule;
$pshost = $s2config.TillConfig.printing.usbprintserverhost;
$psport = $s2config.TillConfig.printing.usbprintserverport;
#---- Share Print Client Config
$printclient = $s2config.TillConfig.printing.isnetworkprintclient;
$jposprintstring = $s2config.TillConfig.printing.PSprinterjposstring;
$ipreceptprtreq = $s2config.TillConfig.printing.isstorereceptprintip;
$receptprtip = $s2config.TillConfig.printing.ipreceptlocal;
$ipprintjposstr = $s2config.TillConfig.printing.ipprinterjposstring;
$ipCashDrawConnected = $s2config.TillConfig.printing.cashDrawConnectedViaKickport;
$ipCashHWPath = $s2config.TillConfig.Program.ipCashDrawHWConfPathName;
#---- Bog standard USB Config
$isbogstandard = $s2config.TillConfig.printing.bogstandardusbprt;
#----PED Config 
$pednum = $s2config.TillConfig.peds.howmanypeds;
$pedip1 = $s2config.TillConfig.peds.pedip1;
$pedip2 = $s2config.TillConfig.peds.pedip2;
$pedip3 = $s2config.TillConfig.peds.pedip3;
$pedip4 = $s2config.TillConfig.peds.pedip4;
$pedip5 = $s2config.TillConfig.peds.pedip5;

#logical names
#--- hwconfigxml
$filenamehw = ([string]$hwconfigpath -split '\\')[-1]
$pathhw = ($hwconfigpath -replace $filenamehw, "")
$pathhw = $pathhw.TrimEnd("\")
#--- jposxml Version 1 edition
$jposv1configpath = "$pathhw\version1\jpos.xml";
$filenamejpv1 = ([string]$jposv1configpath -split '\\')[-1]
$pathjpv1 = ($jposv1configpath -replace $filenamejpv1, "")
$pathjpv1 = $pathjpv1.TrimEnd("\")
#--- System.properties 
$filenamexstsysprop = ([string]$xstoresysprop -split '\\')[-1]
$pathxstsysprop = ($xstoresysprop  -replace $filenamexstsysprop, "")
$pathxstsysprop = $pathxstsysprop.TrimEnd("\")
#--- base-xstore.properties - Environment
$filenameenv = ([string]$xenvironbaseconfigloc -split '\\')[-1]
$pathenv = ($xenvironbaseconfigloc -replace $filenameenv, "")
$pathenv = $pathenv.TrimEnd("\")
#--- base-xstore.properties - xstore
$filenamebxs = ([string]$xstorebaseconfigloc -split '\\')[-1]
$pathbxs = ($xstorebaseconfigloc -replace $filenamebxs, "")
$pathbxs = $pathbxs.TrimEnd("\")
#--- Pcs.Properties - Epson Port com service
$filenamepcs = ([string]$pcsproppath -split '\\')[-1]
$pathpcsprop = ($pcsproppath -ireplace $filenamepcs, "")
$pathpcsprop = $pathpcsprop.TrimEnd("\")

#what config gets edited?
$corrdirUSBServ = 'terminalip'#usbprinter share server
$corrdirIPrecpt = 'terminalip' #ip recipt printer
$corrdirShareclient = 'terminalip'#xstore printer share client
$corrdirstdusb = 'terminal' #bog standard USB recipt printer


#functions -------------
#Writes stuff to the log.
Function Write-Log {
    param(
        [Parameter(Mandatory=$true)][String]$msg
    )

    $logtime = (get-date -Format "HH:mm:ss-ddMMyy")
    "$logtime$msg" -replace ":", ''
    Add-Content $loggingpath $logtime$msg
}

#Create Basic script directories.
Function Set-DScript-DIRs {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CREATING SCRIPT DIRS <<<"
Write-Log "   "


    Write-log " : Creating c:\Denby"
    New-Item -ItemType Directory -Path c:\ -Name Denby -Force -ErrorAction SilentlyContinue
    Write-log " : Creating c:\Denby\Scripts"
    New-Item -ItemType Directory -Path c:\Denby -Name Scripts -Force -ErrorAction SilentlyContinue
    Write-log " : Creating c:\Denby\Scripts\Logs"
    New-Item -ItemType Directory -Path c:\Denby\Scripts -Name Logs -Force -ErrorAction SilentlyContinue
}

#Get configuration for PCS.Properties
Function Get-Epson-Ephemeral-Port {
    Write-Log "   "
    Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Checking the Epson Virtual Ports <<<"
    Write-Log "   "
        
        #Backup current pcs.properties file
        Write-log " : backing up pcs.properties to $pcsproppath.orig.backup.$runid."
        Copy-Item -Path $pcsproppath -Destination "$pcsproppath.orig.backup.$runid" -Force

        #Count the number of enteries in the pcs propterties file
        $pcspropxml = [xml](get-content -Path $pcsproppath)
        $global:numofeffport = ($pcspropxml.xmlroot.type.Value | Where-Object {$_ -ilike "ESDPRT*"}).Count
        Write-log " : $numofeffport epson virtual printer ports have been detected in $pcsproppath."

        #Get variables for later use.
        foreach($effport in ($pcspropxml.xmlroot.type)){
            foreach($prop in $effport.property | Where-Object {$_.ID -ieq "PortName"}){
                    if(($prop).value -ilike "*usb*"){
                                $global:notethernetprot= $effport.value
                                Write-log " : $notethernetprot is not a ethernet port, Is a USB Port."
                                }else{
                                        try{
                                            if($prop.value -ieq '${ipprinter}'){
                                                    $global:ethernetportval = $effport.value
                                                    $global:pcpropnetportval = ($prop).value
                                                    Write-log " : $ethernetportval Has been detected as an ethernet printer @ $pcpropnetportval."
                                                }else{
                                                    [System.Net.IPAddress] ($prop).value
                                                    #Ethernet Virtual Port Name
                                                    $global:ethernetportval = $effport.value
                                                    #Ethernet Virtual Port Address
                                                    $global:pcpropnetportval = ($prop).value
                                                    Write-log " : $ethernetportval Has been detected as an ethernet printer @ $pcpropnetportval."
                                                }
                                        }catch{
                                            #Any other Ports configured.
                                            $global:bunkepsonport= $effport.value
                                            Write-log " : $bunkepsonport is not a ethernet port or a USB Port."
                                        }
                                }
                    }
                }

}

#Parse and edit the configpath.
Function Set-Hardware-Configpath {
                    param(
                            [Parameter(Mandatory=$true)][String]$replacewith
                        )
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ EDITIING CONFIGPATH <<<"
Write-Log "   "

    if(Test-Path -Path $xstorebaseconfigloc){

                    #-------------- Xstore-Base config Path --------------#
                    $confpathbasedir = ([string]$xstorebaseconfigloc -ireplace 'base-xstore.properties', '').TrimEnd('\')
                    #backingup configpath file original
                    Write-log " : Backing up base-xstore.properties to $confpathbasedir\base-xstore.properties.cnfedit.bak.$runid"
                    Copy-Item -Path $xstorebaseconfigloc -Destination "$confpathbasedir\base-xstore.properties.cnfedit.bak.$runid" -Force
                                
                                Write-log " : Configuring xstore-baseconfig configuration path."
                                $confpathcont = Get-Content -Path $xstorebaseconfigloc   
                                $ai = 0
                                    foreach($line in $confpathcont){
                                        $ai += 1
                                        if($line -ilike 'xstore.config.path.global.extensions*'){
                                            Write-log " : Line($ai) is holding the config.path.global.extensions."
                                                $arrno = 0
                                                        $linearr = @($line.Split(':'))
                                                            foreach($seg in $linearr){
                                                                $arrno += 1
                                                                        if($seg -ilike "hardware/*"){
                                                                            Write-log " : Replacing $seg with $replacewith."
                                                                            $global:replacewith = $replacewith.Trim()
                                                                            $seg = ""
                                                                            $seg = "$replacewith"
                
                                                                            $linearr[$arrno -1] = $seg
                                                                            $line = [string]$linearr -replace " ", ':'
                
                                                                            Write-log " : ($line) will now be written to config file"
                                                                            $confpathcont[$ai -1] = $line
                                                                            $confpathcont | Set-Content $xstorebaseconfigloc
                                                                        }
                                                            }
                                        }
                                    }

                                    #-------------- Xstore-base config Path, mobile part. --------------#            
                                    Write-log " : Configuring mobile configuration path."
                                    $confpathcont = Get-Content -Path $xstorebaseconfigloc 
                                    $ai = 0
                                        foreach($line in $confpathcont){
                                                        $ai += 1
                                                        if($line -ilike 'mobile.xstore.config.path.global.extensions*'){
                                                            Write-log " : Line($ai) is holding the config.path.global.extensions."
                                                                $arrno = 0
                                                                        $linearr = @($line.Split(':'))
                                                                            foreach($seg in $linearr){
                                                                                $arrno += 1
                                                                                        if($seg -ilike "hardware/*"){
                                                                                            Write-log " : Replacing $seg with $replacewith."
                                                                                            $global:replacewith = $replacewith.Trim()
                                                                                            $seg = ""
                                                                                            $seg = "$replacewith"
                                
                                                                                            $linearr[$arrno -1] = $seg
                                                                                            $line = [string]$linearr -replace " ", ':'
                                
                                                                                            Write-log " : ($line) will now be written to config file"
                                                                                            $confpathcont[$ai -1] = $line
                                                                                            $confpathcont | Set-Content $xstorebaseconfigloc
                                                                                        }
                                                                            }
                                                        }
                                        }
    }else{
        Write-Log " : ERROR - Cannot find $xstorebaseconfigloc. EXIT 1"
        exit 1
    }
}

#Set the JDK bin path in the Path var just for this session.
Function Set-JDK-to-Path {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ADDING JDK TO THE PATH <<<"
Write-Log "   "

    #get path as array
    $patharr = ($Env:PATH).Split(';')
    
    if($patharr -icontains "C:\Program Files\Java\jdk-$jdkver\bin"){
    Write-log " : Path allready contains JDK version $jdkver Bin dir (C:\Program Files\Java\jdk-$jdkver\bin)."
    }ELSE{
    Write-log " : Adding C:\Program Files\Java\jdk-$jdkver\bin to path for THIS POWERSHELL SESSION ONLY."
    $Env:PATH.TrimEnd(';')
    $Env:PATH += ";C:\Program Files\Java\jdk-$jdkver\bin;"
    }

}

#if xstore is running, this will close it.
function close-xstore {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CLOSING XSTORE <<<"
Write-Log "   "

$xstoreanchors = @('C:\xstore\tmp\xstore.anchor','C:\xstore\tmp\dataserver.anchor','C:\environment\tmp\xenv_eng.anchor','C:\environment\tmp\xenv_ui.anchor','C:\xstore-mobile\tmp\xstore_mobile.anchor') 

    if($autoclosexstore -eq "Yes" -or $autoclosexstore -eq "Y"){

            if((Get-Process | Where-Object {$_.Processname -like "xstore*" -or $_.Processname -ilike "xenviro*" -or $_.Processname -ilike "xmobi*"}).count -gt "0"){

                            write-Log " : Xstore Seems to be running, closing."
                            ForEach ($o in $xstoreanchors) {

                                if (Test-Path $o) {
                                    Remove-Item $o -Force
                                    write-Log " : $o has been deleted"
                                }

                                else {
                                    write-Log " : $o doesn't exist"
                                }

            }
        
                            write-Log " : Sleeping for 30 secons to allow xstore to close." 
                            Start-Sleep -Seconds 30

                                if((Get-Process | Where-Object {$_.Processname -like "xstore*"}).count -gt "0"){

                                    write-Log " : ERROR Xstore is still running, exit 1"
                                    exit 1

                                    }else{

                                    write-Log  " : Xstore is not running."
                                }
            

            }else{

            write-Log  " : Xstore is not running, no need to do anything."

    }

        
    }else{

    write-Log  " : No Shutdown Requested. $YN recived."

    }

}

#Unpacks a the hardware folder of denby-config.jar ready for editing.
function Test-Xstore-print-Req {
    
    #Clean up before Fresh Extraction.
    Invoke-Cleanup

Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DEN-CONFIG.JAR DECOMPILE <<<"
Write-Log "   "
#May Aswell only extract the Jar file once, test to see if its required.
    
    if($isprintserver -ilike "Y*" -or $printclient -ilike "Y*" -or $ipreceptprtreq -ilike "Y*" -or $isbogstandard -ilike "Y*"){
        Write-Log " : Xstore Print Configuration is required."

                if(Test-Path -Path $hwconfigpath){
                            Write-Log " : $hwconfigpath exists as specified."

                            #backing up denconfig jar original
                            Copy-Item -Path $hwconfigpath -Destination "$pathhw\$filenamehw.bak.$runid" -Force

                            #unpack the hardware folder of the Jar file.
                            Write-Log " : Unpacking $filenamehw"
                            Start-Process 'Jar' -ArgumentList "-xvf $filenamehw hardware/" -WorkingDirectory $pathhw #Extract Hardware Folder
                            Start-Process 'Jar' -ArgumentList "-xvf $filenamehw version1/" -WorkingDirectory $pathhw #Extract Version 1 folder
                            Start-Sleep 20

                }else{
                Write-Log " : Printer Configuration not required."
                }
    }
}

#Cleans up
function Invoke-Cleanup {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CLEANING UP <<<"
Write-Log "   "

        $filesToDelete = @("$pathhw\hardware","$pathhw\version1","C:\installXstore.cmd","C:\Denby\Scripts\installXstore-WithRebootCheck.ps1","C:\retaildata","C:\Staging","C:\MININT", "C:\data-loader.exe","C:\Failures.html")

        foreach($item in $filesToDelete){
                    Write-log " : Trying to clean up $item."
                    Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue
                        if(test-path -Path $item){
                            Write-log " : WARN - $item has not been deleted, manual deletion is required."
                        }else{
                            Write-log " : $item has been deleted or never existed."
                        }
        }
}

#re-compiles the Denby-config.jar once we have edited the files.
function Invoke-Repack-Config-Jar {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ REPACKING THE JAR <<<"
Write-Log "   "                    

                    #Re-Pack hardware in to jar
                    if(test-path -Path "$pathhw\hardware"){
                            #Packing modified files back in to denby-config.jar
                            Write-log " : Repacking Jar at $pathhw\hardware"
                            Start-Process 'Jar' -ArgumentList "-uf $filenamehw hardware/" -WorkingDirectory $pathhw
                            Start-Sleep 10
                    }else{
                            Write-log " : $pathhw\hardware does not exsits, cannot Repack Jar."  
                    }  
                    
                    #Re-Pack version1 Folder in to Jar
                    if(test-path -Path "$pathhw\version1"){
                            #Packing modified files back in to denby-config.jar
                            Write-log " : Repacking Jar at $pathhw\version1"
                            Start-Process 'Jar' -ArgumentList "-uf $filenamehw version1/" -WorkingDirectory $pathhw
                            Start-Sleep 10
                    }else{
                            Write-log " : $pathhw\version1 does not exsits, cannot Repack Jar."  
                    }   
}

#Adds the config for this machine to be a xStore Print server
Function Add-Print-Server-Xstore {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONFIGURING XSTORE PRINT SHARE CLIENT <<<"
Write-Log "   "

        if(test-path -Path "$pathhw\hardware\$corrdirUSBServ"){
            Write-Log " : $pathhw\hardware\$corrdirUSBServ exists, no need to create."
            }else{
            Write-Log " : $pathhw\hardware\$corrdirUSBServ does not exist, creating now."
            New-Item -ItemType Directory -Path "$pathhw\hardware" -Name "$corrdirUSBServ" -Force
            Copy-Item -Path ".\dependencies\xml\mobile_config.xml" -Destination "$pathhw\hardware\$corrdirUSBServ\HardwareConfig.xml"
            }

            #Define the location of the correct configuration.
            $configfile = "$pathhw\hardware\$corrdirUSBServ\HardwareConfig.xml"
            
            #If mobileconfig is empty then copy over default
            $xmlfile = [XML](Get-Content $configfile)
            if($xmlfile -eq $null -or $xmlfile -eq ""){Write-Log " : Checking to see if the hardware config is empty."

                Write-Log " : Hardware config is empty, copying over default to location."
                    Copy-Item -Path '.\xml\mobile-default.xml' -Destination "$pathhw\hardware\$corrdirUSBServ" -Force
                }

                                        #creating element then moving to top of <hardware>
                                        $rportnode = $xmlfile.hardware.AppendChild($xmlfile.CreateElement("PrintTargetFromRemote"))
                                        $xmlfile.hardware.InsertBefore($rportnode, $xmlfile.Hardware.FirstChild)
                                        $rportnode.SetAttribute("dtype","Integer")
                                        $rportnode.AppendChild($xmlfile.CreateTextNode($psport)) | Out-Null

                                                #creating element then moving to top of <hardware>
                                                $sharenode = $xmlfile.hardware.AppendChild($xmlfile.CreateElement("RemotePrintPort"))
                                                $xmlfile.hardware.InsertBefore($sharenode, $xmlfile.Hardware.FirstChild)
                                                $sharenode.SetAttribute("dtype","string")
                                                $sharenode.AppendChild($xmlfile.CreateTextNode("RECEIPT")) | Out-Null

                                                        #The rest of the nodes are appended not moved.
                                                        $devnode = $xmlfile.hardware.AppendChild($xmlfile.CreateElement("Device"))
                                                        $devnode.SetAttribute("type","POSPrinter")
                                                        $devnode.SetAttribute("use","RECEIPT")

                                                            $enablednode = $devnode.AppendChild($xmlfile.CreateElement("Enabled"))
                                                            $enablednode.SetAttribute("dtype","Boolean")
                                                            $enablednode.AppendChild($xmlfile.CreateTextNode("True")) | Out-Null

                                                                $namenode = $devnode.AppendChild($xmlfile.CreateElement("name"))
                                                                $namenode.SetAttribute("dtype","String")
                                                                $namenode.AppendChild($xmlfile.CreateTextNode("$jposprintstring")) | Out-Null

                                                                    $codnode = $devnode.AppendChild($xmlfile.CreateElement("dtvClaimOnDemand"))
                                                                    $codnode.SetAttribute("dtype","Boolean")
                                                                    $codnode.AppendChild($xmlfile.CreateTextNode("True")) | Out-Null

                                                                        #Saving final XML.
                                                                        Write-Log " : Writing XML to $configfile"
                                                                        $xmlfile.save($configfile)

                                                                            #can mess up multipull runs if we dont despose of thease variables.
                                                                            Remove-Variable devnode,devnode2,enablednode,enablednode2,namenode,namenode2,codnode,codnode2,sharenode,rportnode,xmlfile
                                                                            $global:printshareconfigured = 'Yes'

                        #Add the firewall rule if requested,
                        if($fwreq -ieq "y" -or $fwreq -ieq "yes"){
                
                            New-NetFirewallRule -DisplayName "Xstore Printer Sharing IN" -Direction inbound -Profile DOMAIN -Action Allow -LocalPort $psport -Protocol TCP
                                
                                
                                $ConfiguredFWrules = (Get-NetFirewallRule -DisplayName *).DisplayName
                                if($ConfiguredFWrules -icontains "Xstore Printer Sharing IN"){
                                    Write-Log " : Firewall rule for print sharing was added (port $psport, TCP)"
                                    $global:printshareconfw = 'Yes'
                                }else{
                                    Write-Log " : ERROR, Firewall rule for print sharing not found, please add manually (port $psport, TCP)."
                                    $global:printshareconfw = 'ERROR'
                                }
                            
                
                            }else{

                            Write-Log " : Firewall rule for print sharing was not added, returned with $fwreq"
                        }
        
        #Set the hardware config path to this configuration.
        Set-Hardware-Configpath -replacewith "hardware/$corrdirUSBServ"

}

#Adds the config for this machine to be a xstore Print server CLIENT
Function Add-Printer-Share-Client {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONFIGURING USB Printer Share <<<"
Write-Log "   "

            if(test-path -Path "$pathhw\hardware\$corrdirShareclient"){
                Write-Log " : $pathhw\hardware\$corrdirShareclient exists, no need to create."
            }else{
                Write-Log " : $pathhw\hardware\$corrdirShareclient does not exist, creating now."
                New-Item -ItemType Directory -Path "$pathhw\hardware" -Name "$corrdirShareclient" -Force
                Copy-Item -Path ".\dependencies\xml\hwcfgdf.xml" -Destination "$pathhw\hardware\$corrdirShareclient\HardwareConfig.xml"
            }

            if($printclient -ilike "y*"){Write-Log " : XML config states that this is a network share printer client."
            
                    $jposprintstring = "Epson-Printer-XstoreSharing"

                    #Backup v1Jpos.xml
                    Copy-Item -Path $jposv1configpath -Destination "$pathjpv1\$filenamejpv1.bak.$runid"
                    Write-Log " : Making Jpos Config Backup to $pathjpv1\$filenamejpv1.bak.$runid."

                    $jposv1xml = [xml](Get-Content $jposv1configpath);
                    Write-Log " : Reading in $jposv1configpath"

                    #V1 jpos config.
                    if($jposv1xml -eq $null){
                        Write-Log " : JPOS config is empty, copying over default to location."
                            Copy-Item -Path '.\xml\jpos.xml' -Destination $jposv1configpath -Force
                    }

                    #setup v1 jpos.xml
                    #--- setting port
                    Write-Log " : Changing Values in v1 Jpos.xml to ones stored in stage 2 var xml file."
                    foreach ($node in ($jposv1xml.JposEntries.JposEntry | Where-Object {$_.logicalName -eq $jposprintstring})){
                                foreach($hp in ($node.prop | Where-Object {$_.name -eq "hostPort"})){
                                        $hp.SetAttribute("value", $psport)
                                        $jposv1xml.Save($jposv1configpath)
                                        Write-Log " : Set Host Port to $psport."
                                            Start-Sleep 2
                                        }
                    }
                    #--- setting host
                    foreach ($node in ($jposv1xml.JposEntries.JposEntry | Where-Object {$_.logicalName -eq $jposprintstring})){
                                foreach($hp in ($node.prop | Where-Object {$_.name -eq "host"})){
                                        $hp.SetAttribute("value", "$pshost")
                                        $jposv1xml.Save($jposv1configpath)
                                        Write-Log " : Set Host name to $pshost."
                                            Start-Sleep 2
                                        }
                    }
            
                    #setting up printer in hardwareconfig.xml
                    #--- adding printer record to end of </device>

                    $configfile = "$pathhw\hardware\$corrdirShareclient\HardwareConfig.xml"
                    $xmlfile = [XML](Get-Content $configfile)
                    if(Test-Path -Path $configfile){
                        Write-Log " : $configfile exists."
                                            
                                            Write-Log " : Writing new device nodes."
                                            $devnode = $xmlfile.hardware.AppendChild($xmlfile.CreateElement("Device"))
                                            $devnode.SetAttribute("type","POSPrinter")
                                            $devnode.SetAttribute("use","RECEIPT")

                                                $enablednode = $devnode.AppendChild($xmlfile.CreateElement("Enabled"))
                                                $enablednode.SetAttribute("dtype","Boolean")
                                                $enablednode.AppendChild($xmlfile.CreateTextNode("True")) | Out-Null

                                                $namenode = $devnode.AppendChild($xmlfile.CreateElement("name"))
                                                $namenode.SetAttribute("dtype","String")
                                                $namenode.AppendChild($xmlfile.CreateTextNode("$jposprintstring")) | Out-Null

                                                                    $xmlfile.save($configfile)
                                                                    Write-Log " : Writing XML to $configfile."

                                                                        #can mess up multiple runs if we dont despose of thease variables.
                                                                        Remove-Variable devnode,devnode2,enablednode,enablednode2,namenode,namenode2,xmlfile

                                                                                #Set the hardware config path to this configuration.
                                                                                Set-Hardware-Configpath -replacewith "hardware/$corrdirShareclient"

                        }else{

                        Write-Log " : ERROR, config file does not exist at $configfile."

                        }

                    

                }else{

                Write-Log " : XML config states that its not a shared print client"

                }
}

#Configures the Ped IPs
Function Set-Ped-IP {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONFIGURING PED IP <<<"
Write-Log "   "

    Write-Log " : XML file states that there are $pednum PEDS in this store"
    if($pednum -gt '0'){

        #backingup Main Ocius config
        Write-Log " : Backing up properties file to ($eftlinkdir\ocius.properties.bak.$runid)"
        Copy-Item -Path "$eftlinkdir\ocius.properties" -Destination "$eftlinkdir\ocius.properties.bak.$runid" -Force

            foreach($pedconf in 1..$pednum){
                    
                if(Test-Path -Path "$eftlinkdir\server$pedconf\ocius.properties"){
                    
                    #backingup ocius config file original
                    Write-Log " : Backing up properties file to ($eftlinkdir\server$pedconf\ocius.properties.bak.$runid)"
                    Copy-Item -Path "$eftlinkdir\server$pedconf\ocius.properties" -Destination "$eftlinkdir\server$pedconf\ocius.properties.bak.$runid" -Force
                    

                    $pedindconf = Get-Content -Path "$eftlinkdir\server$pedconf\ocius.properties"
                    Write-Log " : Reading in config file located at ($eftlinkdir\server$pedconf\ocius.properties)"
                        
                        $pedip = Get-Variable -Name ("pedip"+$pedconf) -ValueOnly
                        $ai = 0
                        
                                    foreach($line in $pedindconf){
                            
                                        $ai += 1

                                        if($line -like "ip.address*"){
                                        Write-Log " : Found IP address connfig, currently set to ($line)"

                                            $currentipws = $line.split("=")[1]
                                                $currentipws = $currentipws.Trim()
                                                    Write-Log " : Current IP address set to $currentipws"
                                                    Write-Log " : New IP address is to be set to $pedip"

                                                $line = $line -replace "= ", "="
                                                $line = $line -replace "ip.address =$currentipws", "ip.address = $pedip"
                                    
                                                Write-Log " : Writing $line to server$pedconf\ocius.properties"
                                                $pedindconf[$ai-1] = $line
                                    
                                            }else{
                                            #line is not ip address line.
                                            }
                                    }


                            Write-Log " : Writing out new config file at $eftlinkdir\server$pedconf\ocius.properties"
                            $pedindconf  | Set-Content "$eftlinkdir\server$pedconf\ocius.properties"

                            $pedindconf = Get-Content -Path "$eftlinkdir\server$pedconf\ocius.properties"
                            Write-Log " : Checking current IP config for $eftlinkdir\server$pedconf\ocius.properties."
                                foreach($line in $pedindconf){
                                if($line -like "ip.address*"){
                                    $currentip = $line.split("=")[1]
                                    Write-Log " : The new ip for server$pedconf is set to $currentip."
                                    }
                                }
                        }else{
                        "$eftlinkdir\server$pedconf\ocius.properties does not exist"
                        }
            }
    }else{
        Write-Log " : there are $pednum peds in this store, no configuration is required."
    }
}

#Configure IP Recept Printer
Function Set-IP-Recept-Printer {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONFIGURING IP PRINTER <<<"
Write-Log "   "

            if(Test-Path -Path .\dependencies\properties\pcsprop.eth){
                    

                        #Editing base system.properties BASE -----------------------------
                        #editing printer name
                        $xstoresyspropcnt = Get-Content C:\xstore\updates\xstore.properties
                        $linecnt = 0
                        $corrline = 0
                            foreach($ln in $xstoresyspropcnt){
                                $linecnt += 1
                                if($ln -ilike "den.ipprinter.name*"){
                                    $corrline = $linecnt-1
                                    $ln = $ln -ireplace ' ', ''
                                    $currentipprtnm = ($ln.Split('=')[1])
                                    $currentipprtnm = $currentipprtnm.Trim()
                                        Write-Log " : Currently, the ip printer name configured is '$currentipprtnm', reconfiguring to '$ipprintjposstr' on line $corrline."
                                        $ln = $ln.Replace("$currentipprtnm","$ipprintjposstr")
                                        $xstoresyspropcnt[$corrline] = $ln
                            
                                }else{
                                #thease are not the droids you are looking for.
                                }
                            }

                        #edititing printer IP
                        $linecnt = 0
                        $corrline = 0
                            foreach($ln in $xstoresyspropcnt){
                                $linecnt += 1
                                if($ln -ilike "den.ipprinter.host*"){
                                    $corrline = $linecnt-1
                                    $ln = $ln -ireplace ' ', ''
                                    $currentip = ($ln.Split('=')[1])
                                    $currentip = $currentip.Trim()
                                        Write-Log " : Currently, the ip printer ip address configured is '$currentip', reconfiguring to '$receptprtip' on line $corrline."
                                        $ln = $ln.Replace("$currentip","$receptprtip")
                                        $xstoresyspropcnt[$corrline] = $ln
                                        $xstoresyspropcnt | Set-Content C:\xstore\updates\xstore.properties
                            
                                }else{
                                #thease are not the droids you are looking for.
                                }
                            }
                        
                        #SYSPROP for mobile -----------------------------
                        if(test-path -path $xstoresyspropmob){
                                $xstoresyspropcnt = Get-Content $xstoresyspropmob
                                $linecnt = 0
                                $corrline = 0
                                    foreach($ln in $xstoresyspropcnt){
                                        $linecnt += 1
                                        if($ln -ilike "den.ipprinter.name*"){
                                            $corrline = $linecnt-1
                                            $ln = $ln -ireplace ' ', ''
                                            $currentipprtnm = ($ln.Split('=')[1])
                                            $currentipprtnm = $currentipprtnm.Trim()
                                                Write-Log " : Currently, the ip printer name configured is '$currentipprtnm', reconfiguring to '$ipprintjposstr' on line $corrline."
                                                $ln = $ln.Replace("$currentipprtnm","$ipprintjposstr")
                                                $xstoresyspropcnt[$corrline] = $ln
                            
                                        }else{
                                        #thease are not the droids you are looking for.
                                        }
                                    }

                                        $linecnt = 0
                                        $corrline = 0
                                            foreach($ln in $xstoresyspropcnt){
                                                $linecnt += 1
                                                if($ln -ilike "den.ipprinter.host*"){
                                                    $corrline = $linecnt-1
                                                    $ln = $ln -ireplace ' ', ''
                                                    $currentip = ($ln.Split('=')[1])
                                                    $currentip = $currentip.Trim()
                                                        Write-Log " : Currently, the ip printer ip address configured is '$currentip', reconfiguring to '$receptprtip' on line $corrline."
                                                        $ln = $ln.Replace("$currentip","$receptprtip")
                                                        $xstoresyspropcnt[$corrline] = $ln
                                                        $xstoresyspropcnt | Set-Content $xstoresyspropmob
                            
                                }else{
                                #thease are not the droids you are looking for.
                                }
                            }
                        
                        }else{
                            write-log " : No Mobile configuration detected, not setting mobile hardware config IP."
                        }


                        #copy over correct pcs.properties file for ethernet printers.
                        if(Test-Path -Path .\dependencies\properties\pcsprop.eth){

                                #Copy over correct PCS.properties file (no need to edit).
                                $sourceHash = (Get-FileHash -Path .\dependencies\properties\pcsprop.eth -Algorithm SHA512).Hash
                                Write-Log " : hash for pcsprop.eth is $sourceHash"
                                $destHash = (Get-FileHash -Path $pcsproppath -Algorithm SHA512).Hash
                                Write-Log " : hash for $pcsproppath is $destHash"

                                if($sourceHash -eq $destHash){
                                    Write-Log " : No need to replace pcs.properties file, files are the same."
                                }else{
                                    Write-Log " : Replacing original pcs.properties file with the correct Ethernet file."
                                    Copy-Item -Path .\dependencies\properties\pcsprop.eth -Destination $pcsproppath -force
                                        if($sourceHash -eq (Get-FileHash -Path $pcsproppath -Algorithm SHA512).Hash){
                                                Write-Log " : Ethernet PCS.properties file copy successfull, hashes match."
                                                $PCSethernetedit = Get-Content -path $pcsproppath
                                                Write-Log " : Editing pcs.properties with the correct IP of $receptprtip."
                                                $PCSethernetedit = $PCSethernetedit -replace "printerip", "$receptprtip"
                                                $PCSethernetedit | Set-Content -Path $pcsproppath -Force
                                            
                                            }else{
                                                Write-Log " : ERROR - Ethernet PCS.properties file copy error, hashes do not match."
                                            }
                                }
                        }


    }else{
        Write-Log " : ERROR - files for Ethernet receipt printing not found, printer not added."
    }

    #Updated to allow for cashdraws connected via IP printer kick port.
    if($ipCashDrawConnected -ilike "y*"){
        #Set the hardware config path to this configuration.
        Set-Hardware-Configpath -replacewith "hardware/$ipCashHWPath"
    }else{
        #Set the hardware config path to this configuration.
        Set-Hardware-Configpath -replacewith "hardware/$corrdirIPrecpt"
    }
}

#Setup the a till with a usb receipt printer, nothing else. 
Function set-standard-usb-setup {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ BOGSTANDARD USB PRINTER SETUP <<<"
Write-Log "   "

    if(Test-Path -Path ".\dependencies\properties\pcsprop.usb"){

        #Copy over correct PCS.properties file (no need to edit).
        $sourceHash = (Get-FileHash -Path ".\dependencies\properties\pcsprop.usb" -Algorithm SHA512).Hash
        Write-Log " : hash for pcsprop.usb is $sourceHash"
        $destHash = (Get-FileHash -Path $pcsproppath -Algorithm SHA512).Hash
        Write-Log " : hash for $pcsproppath is $destHash"

        if($sourceHash -eq $destHash){
            Write-Log " : No need to replace pcs.properties file, files are the same."
        }else{
            Write-Log " : Replacing original pcs.properties file with the correct USB file."
            Copy-Item -Path ".\dependencies\properties\pcsprop.usb" -Destination $pcsproppath -force
                if($sourceHash -eq (Get-FileHash -Path $pcsproppath -Algorithm SHA512).Hash){
                        Write-Log " : USB PCS.properties file copy successfull, hashes match."
                    }else{
                        Write-Log " : ERROR - USB PCS.properties file copy error, hashes do not match."
                    }
        }

        #Set the hardware config path to this configuration.
        Set-Hardware-Configpath -replacewith "hardware/$corrdirstdusb"

    }else{
        Write-Log " : ERROR - files for USB receipt printing not found, printer not added."
    }

}

#Set the firewall rule to allow remote SQL access
Function Set-Remote-SQL-FWR {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ADDING SQL SHARE FIREWALL RULE <<<"
Write-Log "   "

                        #Add the firewall rule if requested,
                        if($sqlfwreq -ieq "y" -or $fwreq -ieq "yes"){
                
                            New-NetFirewallRule -DisplayName "Denby SQL Remote Access" -Direction inbound -Profile DOMAIN -Action Allow -LocalPort 1433-1434 -Protocol TCP
                            
                            Start-Sleep -Seconds 15

                                $ConfiguredFWrules = (Get-NetFirewallRule -DisplayName *).DisplayName
                                if($ConfiguredFWrules -icontains "Denby SQL Remote Access"){
                                    Write-Log " : Firewall rule for Remote SQL access was added (port $psport, TCP) - CONFIRMED."
                                    $global:sqlremotefw = 'Yes'
                                }else{
                                    Write-Log " : ERROR, firewall rule not found, please add manually (port $psport, TCP)."
                                    $global:sqlremotefw = 'No'
                                }
                                            
                            }else{

                            Write-Log " : Firewall rule for Remote SQL access was not requested, returned with $sqlfwreq."
                        }
                        
}

#Take a restore point prior to modification
Function get-Snapshot {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ TAKING SYSTEM RESTORE IMAGE <<<"
Write-Log "   "

$takendate = @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}
$lastTakenDate = (Get-ComputerRestorePoint | Select-Object -Property $takendate, SequenceNumber, Description  -last 1 | Sort-Object -Property SequenceNumber -Descending).Date
$cannotTakeSS = $null

if($lastTakenDate -gt (Get-Date).AddDays(-1)){

    write-log " : A Restore point has allready been taken, cannot take another."
    $cannotTakeSS = $true

}elseif($null -eq $lastTakenDate){

    write-log " : WARN - Cannot gate date of last system restore point, attempting to take one."

    $restdate = Get-date -Format 'ddMMyy'
    Write-Log " : Generating Windows System Restore point."
    Checkpoint-Computer -Description "Before-Denby-Xstore-Stage2-$restdate" -RestorePointType "MODIFY_SETTINGS"

    Write-Log " : Sleeping for 45 seconds."
    Start-Sleep -Seconds 45

}else{

    $restdate = Get-date -Format 'ddMMyy'
    Write-Log " : Generating Windows System Restore point."
    Checkpoint-Computer -Description "Before-Denby-Xstore-Stage2-$restdate" -RestorePointType "MODIFY_SETTINGS"

    Write-Log " : Sleeping for 45 seconds."
    Start-Sleep -Seconds 45
}

    #Check status of system restore point.
    $lastreststatus = Get-ComputerRestorePoint -LastStatus
    Write-Log " : Last restore point status = $lastreststatus"

    $checkforresttore = (Get-ComputerRestorePoint).Description
    if($checkforresttore -icontains "Before-Denby-Xstore-Stage2-$restdate"){
            Write-Log " : SUCCESS, the restore point has been taken."
        }elseif($true -eq $cannotTakeSS){
            Write-Log " : WARN, snapshot cannot be taken, a restore point has allready been taken."
        }else{
            Write-Log " : ERROR, the restore point has not been taken. Exit 1."
        exit 1
        }
}

#Runs xstore / xenviroment configuration bat files. 
Function set-xstore-final {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ RUNNING XSTORE AND ENV CONFIG BATS <<<"
Write-Log "   "
    
    Write-Log " : Running xenvironments configuration scripts."
    $configScripts = @("c:\environment\configure.bat","c:\xstore\baseconfigure.bat","c:\xstore\configure.bat","C:\xstore-mobile\mobile_baseconfigure.bat","C:\xstore-mobile\mobile_configure.bat")

    Foreach($script in $configScripts){
        Write-Log " : Sleeping for 15 seconds."
        Start-Sleep -Seconds 15
        if(test-path -Path $script){
            Write-Log " : $script has been found, running."
            Start-Process "cmd.exe" -ArgumentList "/c $script" -Wait
        }else{
            Write-Log " : WARN - $script cannot be found."
        }
    }

}

#Changes the store number
Function set-store-number {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CHANGING STORE NUMBER <<<"
Write-Log "   "

        Write-Log " : Changing Store Numbers."

        Write-Log " : Backing up original configurations."
        Copy-Item -Path $xstorebaseconfigloc -Destination "$pathbxs\$filenamebxs.bac.$runid" -Force
            Start-Sleep -Seconds 15 
            if(Test-Path -Path "$pathbxs\$filenamebxs.bac.$runid"){
                Write-Log " : Backup of $xstorebaseconfigloc confirmed."
            }else{
                Write-Log " : ERROR Backup of $xstorebaseconfigloc not completed, Exit 1."
                exit 1
            }


        Copy-Item -Path $xenvironbaseconfigloc -Destination "$pathenv\$filenameenv.bac.$runid"
            Start-Sleep -Seconds 15 
            if(Test-Path -Path "$pathenv\$filenameenv.bac.$runid"){
                Write-Log " : Backup of $xenvironbaseconfigloc confirmed."
            }else{
                Write-Log " : ERROR Backup of $xenvironbaseconfigloc not completed, Exit 1."
                exit 1
            }
        
        Write-Log " : Backups Complete."
        Write-Log " : ---- Modiftying $xstorebaseconfigloc."

        $xstorebasefile = get-content -Path $xstorebaseconfigloc
        $linenum = 0

        foreach($line in $xstorebasefile){
            $linenum += 1
            if($line -ilike 'dtv.location.StoreNumber*'){
            Write-Log " : Store number is located on $linenum @ $xstorebaseconfigloc."
            $line = $line -ireplace " ", ""
            $currentstore = $line.Split('=')[1]
            $currentstore = $currentstore.Trim()
            Write-Log " : Replacing old store number ($currentstore) with new store number ($newstorenum)."
            $line = $line -ireplace "dtv.location.StoreNumber=$currentstore", "dtv.location.StoreNumber=$newstorenum"
            $xstorebasefile[$linenum-1] = $line
                
                Write-Log " : Writing changes to $xstorebaseconfigloc."
                $xstorebasefile  | Set-Content $xstorebaseconfigloc

            }else{
            #is not the correct line
            }    
        }

        Write-Log " : ---- Modiftying $xenvironbaseconfigloc."

        $xenvbasefile = get-content -Path $xenvironbaseconfigloc
        $linenum = 0

        foreach($line in $xenvbasefile){
            $linenum += 1
            if($line -ilike 'installx.rtlLocId*'){
            Write-Log " : Store number is located on $linenum @ $xenvironbaseconfigloc."
            $line = $line -ireplace " ", ""
            $currentstore = $line.Split('=')[1]
            $currentstore = $currentstore.Trim()
            Write-Log " : Replacing old store number ($currentstore) with new store number ($newstorenum)."
            $line = $line -ireplace "installx.rtlLocId=$currentstore", "installx.rtlLocId=$newstorenum"
            $xenvbasefile[$linenum-1] = $line
                
                Write-Log " : Writing changes to $xenvironbaseconfigloc."
                $xenvbasefile | Set-Content $xenvironbaseconfigloc

            }else{
            #is not the correct line
            }    
        }
        
        #Correction to store number change by OLR
        Start-Process 'sqlcmd' -ArgumentList "-S localhost -U dtv -P $dvtdbuserpass -v OrgID=1 StoreID=$newstorenum CountryID='GB' CurrencyID='GBP' -i C:\xstore\database\ClientData.sql -o $logDIR\SQLChangeStoreNumberOutput.$runid.log"

        #Park Retail Modifications at Peters Request.
        if($pridcnreq -ilike "*y*"){
            Write-Log " : Reading in Park Retail Store to ID map from $pridmaploc."
            $pridmap = [xml](get-content -Path $pridmaploc); 
            $correctmap = $pridmap.prids.store | Where-Object {$_.storenum -ieq "$newstorenum"  }
                if($null -eq $correctmap -or $correctmap -eq ''){
                    Write-Log " : WARNING: Correct map for new store number $newstorenum cannot be found in $pridmaploc, check data is correct. NO CHANGES WILL BE MADE."
                }else{
                    foreach($ociusprop in (Get-ChildItem -Path $eftlinkdir -Recurse | Where-Object {$_.Name -ilike "ocius.properties"})){
                        $ocifilepath = $ociusprop.FullName
                        Write-Log " : Reading in ocius.properties file from $ocifilepath."
                        $ociusfilecont = Get-Content $ociusprop.FullName
                            $correctlinenum = 0
                            foreach($line in $ociusfilecont){
                                $correctlinenum += 1
                                if($line -ilike "flexecash.account.id*"){
                                    Write-Log " : Flexecash ID field found on line:$correctlinenum, sanitising field."
                                    $line = $line.Trim()
                                    $line = $line -replace ' ',''
                                    $global:currentprid = $line.split('=')[1]
                                    $global:newprid = $correctmap.storeprid
                                    Write-Log " : Current value of $currentprid will be replaced with $newprid."
                                    $line = $line -ireplace "$currentprid","$newprid"
                                    $line = $line -ireplace "=", " = "
                                        $ociusfilecont[$correctlinenum -1] = $line
                                        Write-Log " : Saving out buffer to $ocifilepath, replacing old content."
                                        $ociusfilecont | Set-Content -Path $ociusprop.FullName
                                }
                                    
                            }
                    }
                    Write-Log " : Park Retail modifications that have been requested are now complete."
                }
        }else{
            Write-Log " : Park retail change not requested ($pridcnreq). No changes being made."
        }
}

#Add Denby Schedualed Tasks
Function add-sched-tasks {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ADDING SCHEDUALED TASKS <<<"
Write-Log "   "
    
    #Denby windows update management --- WILL RUN AT 9:30PM every tuesday
    $taskName1 = 'denbyWindowsUpdateController'
    $taskDesc1 = 'Will run a script that will update windows if the host name is in a shared txt file on the sdrive.'
    $action1 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -file "auto-windows-update-v20.ps1"' -WorkingDirectory 'C:\Denby\Scripts\'
    $trigger1 =  New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Tuesday -At 9:30PM

    #Database Backup Script only on v20 Servers --- WILL RUN AT a hour between 2am and 4am
    $backupTimeHr= '{0:d2}' -f (Get-Random -Minimum 2 -Maximum 4)
    $backupTimeMM= '{0:d2}' -f (Get-Random -Minimum 1 -Maximum 59)
    $backupTime = [string]$backupTimeHr + ":" + [string]$backupTimeMM
    $taskName2 = 'denbyXstoreDatabaseBackup'
    $taskDesc2 = 'Will run a script that will backup the store database to headoffice.'
    $action2 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -file "backup-xstore-db.ps1"' -WorkingDirectory 'C:\Denby\Scripts'
    $trigger2 =  New-ScheduledTaskTrigger -Daily -At $backupTime

    #xStore Restart --- WILL RUN AT 6am every monday.
    $taskName3 = 'denbyXstoreRestart'
    $taskDesc3 = 'Will run a script that will restart the xstore system.'
    $action3 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -file "xstore-shutdown-restart.ps1"' -WorkingDirectory 'C:\Denby\Scripts'
    $trigger3 =  New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek monday -At 6am

    #Launch xStore at Logon.
    $taskName4 = 'denbyLaunchXstoreAtLogon'
    $taskDesc4 = 'This will launch xStore at logon of any user using the VBS file C:\environment\start_eng.vbs.'
    $action4 = New-ScheduledTaskAction -Execute 'Cscript.exe' -Argument 'C:\environment\start_eng.vbs //nologo' -WorkingDirectory 'C:\Windows\System32'
    $trigger4 =  New-ScheduledTaskTrigger -AtLogOn

    #Update the scripts at 7am every day.
    $taskName5 = 'denbyScriptUpdater'
    $taskDesc5 = 'This script will update all other scripts within the denby scripts folder.'
    $action5 = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -file "xStore-DenbyScriptUpdater.ps1"' -WorkingDirectory 'C:\Denby'
    $trigger5 =  New-ScheduledTaskTrigger -Daily -At 7am 

    $tasks = @("$taskName1","$taskName2", "$taskName3", "$taskName4", "$taskName5")
    
    #add tasks
    Write-Log ' : Adding Windows Updater to Sched Tasks.'
    Register-ScheduledTask -Action $action1 -Trigger $trigger1 -TaskName $taskName1 -Description $taskDesc1 -TaskPath 'Denby' -RunLevel Highest -Force

        #test to see if the host is a instore server.
        if(test-path -Path "C:\Denby\Scripts\backup-xstore-db.ps1"){
            Write-Log ' : Adding DB Backup to Sched Tasks.'
            Register-ScheduledTask -Action $action2 -Trigger $trigger2 -TaskName $taskName2 -Description $taskDesc2 -TaskPath 'Denby' -RunLevel Highest -Force
        }else{
            write-Log " : This does not seem to be a server, not adding DB Backup Script to Schedualed Tasks"
        }

    Write-Log ' : Adding restarter to Sched Tasks.'
    Register-ScheduledTask -Action $action3 -Trigger $trigger3 -TaskName $taskName3 -Description $taskDesc3 -TaskPath 'Denby' -RunLevel Highest -Force

    Write-Log ' : Adding xStore launch at startup to Sched Tasks.'
    Register-ScheduledTask -Action $action4 -Trigger $trigger4 -TaskName $taskName4 -Description $taskDesc4 -TaskPath 'Denby' -Force

    Write-Log ' : Adding script updater to schedualed tasks.'
    Register-ScheduledTask -Action $action5 -Trigger $trigger5 -TaskName $taskName5 -Description $taskDesc5 -TaskPath 'Denby' -Force

    Start-Sleep -Seconds 20
        Foreach($task in $tasks){
            if((Get-ScheduledTask -TaskName *).TaskName -icontains $task){
                Write-Host " : $task has been successfully added to schedualed tasks."
                }else{
                Write-Host " : ERROR, $task has not been added to schedualed tasks."
                }
        }
}

#Enable Auto Logon
Function set-AutoLogon {
    Write-Log "   "
    Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SETTING AUTO LOGON <<<"
    Write-Log "   "

        #Get the domain name and convert to upper case.
        $domain = (((Get-CIMInstance CIM_ComputerSystem).domain).split('.')[0]).ToUpper()

        Write-Log " : Writing the correct keys to the registry, using UNAME:$domain\$env:USERNAME & PASS:$autologonpass."

        #write the values, 
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String -Force
            Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$domain\$env:USERNAME" -type String -Force
            Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$autologonpass" -type String -Force
    
            $regvalue = Get-ItemProperty -Path $RegistryPath
            $AUsuccess = '0'
    
            if($regvalue.DefaultPassword -ieq $autologonpass){
                $AUsuccess += 1
                Write-Log " : Success, auto-logon password has been written to the registry."
            }else{
                Write-Log " : ERROR, auto-logon password is not in the registry at $RegistryPath."
            }
    
            if($regvalue.DefaultUserName -ieq "$domain\$env:USERNAME"){
                $AUsuccess += 1
                Write-Log " : Success, auto-logon username and correct domain have been written to the registry."
            }else{
                Write-Log " : ERROR, auto-logon username or domain is not in the registry at $RegistryPath."
            }
    
            if($regvalue.AutoAdminLogon -ieq '1'){
                $AUsuccess += 1
                Write-Log " : Success, auto-logon has been enabled."
            }else{
                Write-Log " : ERROR, auto-logon has not been enabled."
            }

            #attempting to set up autologn with autologon64.exe
            Start-Process -FilePath 'C:\Denby\Autologon64.exe' -ArgumentList "/accepteula", $env:USERNAME, $domain, $autologonpass -wait
    
}

#Add denby users to db administrators
Function add-denbyto-sql {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SETTING DENBY AS SQL ADMIN <<<"
Write-Log "   "

    $sqlserversrunning = (Get-Process | Where-Object {$_.Name -ilike "*sqlserv*"}).count
    Push-Location

    If($sqlserversrunning -gt '0'){
        $sqladminspre = (Invoke-Sqlcmd -U sa -P $sadbuserpass -InputFile ".\dependencies\sql\admintest.sql").login
            if($sqladminspre -icontains 'DENBYGROUP\G Xstore SQL Admins'){
                Pop-Location
                Write-Log " : WARN, SQL server allready contains DENBYGROUP\G Xstore SQL Admins, doing nothing."
            }else{
                    Write-Log " : Detected SQL server running, adding denby to remote users."
                    Invoke-Sqlcmd -U 'sa' -P $sadbuserpass -InputFile '.\dependencies\sql\XstoreSQLAdmins.sql' | out-null
                    Pop-Location
                    Start-Sleep -Seconds 20
                    $sqladminspost = (Invoke-Sqlcmd -U sa -P $sadbuserpass -InputFile ".\dependencies\sql\admintest.sql").login
                            if($sqladminspost -icontains 'DENBYGROUP\G Xstore SQL Admins'){
                                Pop-Location
                                Write-Log " : Confirming that G Xstore SQL Admins has been added to the users that can logon remotely."
                                $global:sqladminadded = 'Yes'
                            }else{
                                Pop-Location
                                Write-Log " : ERROR, DENBYGROUP\G Xstore SQL Admins has not been added to the database."
                                $global:sqladminadded = 'no'
                            }
            }
        }else{
        Write-Log " : Error, cannot detect running SQL server, server process count is $sqlserversrunning."
        }
}

#Copy Updated Ocius.Keystore Files if requested.
Function Copy-OciusKS {
Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Copying over Correct Ocius.keystore. <<<"
Write-Log "   "

    $sourcehash = (Get-FileHash ".\dependencies\ssl\ocius.keystore" -Algorithm SHA512).Hash
    $locationsOfKS = @('C:\eftlink\data\ocius.keystore','C:\eftlink\server1\data\ocius.keystore','C:\eftlink\server2\data\ocius.keystore','C:\eftlink\server3\data\ocius.keystore','C:\eftlink\server4\data\ocius.keystore','C:\eftlink\server5\data\ocius.keystore')

    foreach($key in $locationsOfKS){

            if(Test-Path -Path $key){

                    Write-Log " : $key copy prerequisites satisfied."

                            #Backup Current Keystores. 
                            Write-Log " : Attempting rename of $loc to act as a backup."
                            Rename-Item -Path $key -NewName "ocius.keystore.original.$runid" -Force
                            if(Test-Path -Path "$key.original.$runid"){
                                    Write-Log " : SUCCESS - Backup of $key detected."

                                    write-log " : Copying .\dependencies\ssl\ocius.keystore to $key"
                                    copy-item -Path ".\dependencies\ssl\ocius.keystore" -Destination $key -Force
                                    $KSCopyHash = (Get-FileHash -Path $key -Algorithm SHA512).Hash

                                        if($sourcehash -ne $KSCopyHash){
                                            Write-Log " : ERROR - Copy of ocius.keystore to $key has failed, CRC Error."
                                        }else{
                                            Write-Log " : Copy of ocius.keystore to $key is good. CRC is Good."
                                        }

                                }else{
                                    Write-Log " : ERROR - Backup of $key failed."
                                }

            }else{
                Write-Log " : ERROR - $_ copy prerequisites fail, cannot find keystore."
            }

    }
}

#Change the store brand.
Function Get-BrandChange {

Write-Log "   "
Write-Log " : ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Changing Store Brand. <<<"
Write-Log "   "

                #-------------- Xstore-Base config Path --------------#
                $confpathbasedir = ([string]$xstorebaseconfigloc -ireplace 'base-xstore.properties', '').TrimEnd('\')
                #backingup configpath file original
                Write-log " : Backing up base-xstore.properties to $confpathbasedir\base-xstore.properties.cnfedit.bak.BRAND.$runid"
                Copy-Item -Path $xstorebaseconfigloc -Destination "$confpathbasedir\base-xstore.properties.cnfedit.bak.BRAND.$runid" -Force

                                
                Write-log " : Configuring xstore-baseconfig configuration path."
                $confpathcont = Get-Content -Path $xstorebaseconfigloc   
                    
                $ai = 0
                    foreach($line in $confpathcont){
                        $ai += 1
                        if($line -ilike 'xstore.config.path.global.extensions*'){
                            Write-log " : Line($ai) is holding the config.path.global.extensions."
                                $arrno = 0
                                        $linearr = @($line.Split(':'))
                                            foreach($seg in $linearr){
                                                $arrno += 1
                                                        if($seg -ilike "brand/*"){
                                                            Write-log " : Replacing $seg with $brand."
                                                            $brand = $brand.Trim()
                                                            $seg = ""
                                                            $seg = "brand/$brand"

                                                            $linearr[$arrno -1] = $seg
                                                            $line = [string]$linearr -replace " ", ':'

                                                            Write-log " : ($line) will now be written to config file"
                                                            $confpathcont[$ai -1] = $line
                                                            $confpathcont | Set-Content $xstorebaseconfigloc
                                                        }
                                            }
                        }
                    }

                    #Edit Mobile Line
                    $confpathcont = Get-Content -Path $xstorebaseconfigloc  
                    $ai = 0
                    foreach($line in $confpathcont){
                        $ai += 1
                        if($line -ilike 'mobile.xstore.config.path.global.extensions*'){
                            Write-log " : Line($ai) is holding the mobile.config.path.global.extensions."
                                $arrno = 0
                                        $linearr = @($line.Split(':'))
                                            foreach($seg in $linearr){
                                                $arrno += 1
                                                        if($seg -ilike "brand/*"){
                                                            Write-log " : Replacing $seg with $brand."
                                                            $brand = $brand.Trim()
                                                            $seg = ""
                                                            $seg = "brand/$brand"

                                                            $linearr[$arrno -1] = $seg
                                                            $line = [string]$linearr -replace " ", ':'

                                                            Write-log " : ($line) will now be written to config file"
                                                            $confpathcont[$ai -1] = $line
                                                            $confpathcont | Set-Content $xstorebaseconfigloc
                                                        }
                                            }
                        }
                    }

                    # Burleigh Specific Changes
                    if($brand -ilike "bur*"){

                                        Write-log " : Brand Burleigh detected, changing email receipt addresses."
                                        
                                        $rcptEmailbLL = 'xstorereceipts@burgessandleigh.co.uk'
                                        # Edit receipt email address sender
                                        $confpathcont = Get-Content -Path $xstorebaseconfigloc  
                                        $ai = 0
                                        foreach($line in $confpathcont){
                                            $ai += 1
                                            if($line -ilike 'dtv.email.default.sender*'){
                                                Write-log " : Line($ai) is holding the dtv.email.default.sender."
                                                    $arrno = 0
                                                            $linearr = @($line.Split('='))
                                                                foreach($seg in $linearr){
                                                                    $arrno += 1
                                                                            if($seg -ilike "*@*"){
                                                                                Write-log " : Replacing $seg with $rcptEmailbLL."
                                                                                $rcptEmailbLL = $rcptEmailbLL.Trim()
                                                                                $seg = ""
                                                                                $seg = $rcptEmailbLL
                    
                                                                                $linearr[$arrno -1] = $seg
                                                                                $line = [string]$linearr -replace " ", '='
                    
                                                                                Write-log " : ($line) will now be written to config file"
                                                                                $confpathcont[$ai -1] = $line
                                                                                $confpathcont | Set-Content $xstorebaseconfigloc
                                                                            }
                                                                }
                                            }
                                        }

                                        # Edit receipt email address from
                                        $confpathcont = Get-Content -Path $xstorebaseconfigloc  
                                        $ai = 0
                                        foreach($line in $confpathcont){
                                            $ai += 1
                                            if($line -ilike 'dtv.email.receipt.from*'){
                                                Write-log " : Line($ai) is holding the dtv.email.receipt.from."
                                                    $arrno = 0
                                                            $linearr = @($line.Split('='))
                                                                foreach($seg in $linearr){
                                                                    $arrno += 1
                                                                            if($seg -ilike "*@*"){
                                                                                Write-log " : Replacing $seg with $rcptEmailbLL."
                                                                                $rcptEmailbLL = $rcptEmailbLL.Trim()
                                                                                $seg = ""
                                                                                $seg = $rcptEmailbLL
                    
                                                                                $linearr[$arrno -1] = $seg
                                                                                $line = [string]$linearr -replace " ", '='
                    
                                                                                Write-log " : ($line) will now be written to config file"
                                                                                $confpathcont[$ai -1] = $line
                                                                                $confpathcont | Set-Content $xstorebaseconfigloc
                                                                            }
                                                                }
                                            }
                                        }
                    }

}

# Start --------------------------------------------------------------------------------------------------------|

$runyn = $(Write-Host "Are you sure you would like to run xstore in store staging? " -NoNewLine)  + $(Write-Host "Please check and EDIT the stage-2-var.xml before running!!!" -ForegroundColor Red) + $(Write-Host "Enter Y or N : " -ForegroundColor yellow -NoNewLine; Read-Host)

if($runyn -eq "y"){ Write-Log " : Yes to start received."


    Write-Log " ------------ Starting RUN, ID:$runid ------------ "

    #Startup Bits for all runs.
    Set-DScript-DIRs
    close-xstore
    get-Snapshot
    Set-JDK-to-Path
    Get-Epson-Ephemeral-Port

    #de-compile the Jar file.
    Test-Xstore-print-Req

    if($isprintserver -ilike "Y*"){ Write-Log " : This run is a print server - Response ($isprintserver)."

        Add-Print-Server-Xstore      
    
    }Else{ Write-Log " : Is not a print server - Response ($isprintserver)." }

    if($ipreceptprtreq -ilike "Y*"){ Write-Log " : This store contains IP Printers - Response ($ipreceptprtreq)."

        Set-IP-Recept-Printer

    }Else{ Write-Log " : Not a store with an IP printer - Response ($ipreceptprtreq)." }

    if($printclient -ilike "Y*"){ Write-Log " : This run is a print share client - Response ($printclient)."

        Add-Printer-Share-Client      
    
    }Else{ Write-Log " : Not a print share client - Response ($printclient)." }

    if($isbogstandard -ilike "Y*"){ Write-Log " : This run is bog standard usb attached printer, not shared - Response ($isbogstandard)."

        set-standard-usb-setup      
    
    }Else { Write-Log " : Not a bog standard USB Printer Store - Response ($isbogstandard)." }

    if($pednum -ne "0"){ Write-Log " : This store has $pednum ped(s) - Response ($pednum)."

        Set-Ped-IP
    
    }Else { Write-Log " : Store has no Peds - Response ($pednum)." }

    if($changestnum -ilike "Y*"){ Write-Log " : Change of store number requested, ($changestnum)."
    
        set-store-number

    }else{ Write-Log " : Change of store numbers was not requested. ($changestnum)" }

    if($enableautologon -ilike "Y*"){ Write-Log " : Auto logon requested. ($enableautologon)."

        set-AutoLogon

    }else{ Write-Log " : Auto logon was not requested. ($enableautologon)." }

    if($updateOcKs -ilike "Y*"){

        Copy-OciusKS

    }else{ Write-Log " : Ocius.keystore replacement not requested. ($updateOcKs)."}

    #Final Bits for all runs
    Get-BrandChange
    Set-Remote-SQL-FWR
    add-denbyto-sql
    Invoke-Repack-Config-Jar
    Invoke-Cleanup
    Set-xstore-final
    add-sched-tasks

    Write-Log " ------------ END RUN, ID:$runid ------------ "

}else{ 
    Write-Log " : $runyn recived, exiting"
    Exit 1
}

"Desposing of all Variables for next run"
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

Exit 0


