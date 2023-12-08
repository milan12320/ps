[CmdletBinding()]
Param ()
    $url = "http://wsus.jenty.by/upd/Axiom3.zip"
    $OutFile = "Axiom3.zip"
    $Log = "InstallAxiom.log"
    $Temp = "$env:windir\Temp"
    $StartMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    $PublicDesktop = "$env:Public\Desktop"

function Write-Log 
{
    Out-File -FilePath "$Temp\$log" -InputObject "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss")  $($args[0])" -Encoding default -Append
}

# Resolve OS architecture (x64 or x32)

if (Test-Path -Path "C:\Program Files (x86)") 
{
    $ProgFiles = "C:\Program Files (x86)"  
    $registry = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    Write-Log "OS architecture is x64"
}
    else 
    { 
        $ProgFiles = "C:\Program Files"
        $registry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        Write-Log "OS architecture is x32"
    }

Write-Verbose "For Win8.1: turn on TLS 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Log "Downloading 'Axiom3.zip' from $url..."
Try 
{
    Invoke-WebRequest -Uri $url -OutFile "$Temp\$OutFile" -ErrorAction Stop
    Write-Log "Done!"
    Write-Log "Unzipping $Temp\$OutFile to $ProgFiles\Axiom3..."
    Expand-Archive -Path "$Temp\$OutFile" -DestinationPath $ProgFiles -Force -ErrorAction Stop
    Write-Log "Done!"
    
    Write-Log "Creating shortcut 'Axiom 3' on $PublicDesktop for All Users..."
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$PublicDesktop\Axiom 3.lnk")
    $Shortcut.TargetPath = "$ProgFiles\Axiom3\axiom.exe"
    $Shortcut.Save()
    Write-Log "Done!"
    
    Write-Log "Creating links in Start Menu..."
    
    New-Item -Path $StartMenu -Name 'Axiom' -ItemType Directory -Force |Out-Null
    Copy-Item -Path "$PublicDesktop\Axiom 3.lnk" -Destination "$StartMenu\Axiom" -Force
    Write-Log "'Axiom 3' shortcut... Done!"

    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$StartMenu\Axiom\Очистить кэш.lnk")
    $Shortcut.TargetPath = "$ProgFiles\Axiom3\bin\ccache.cmd"
    $Shortcut.IconLocation = "%SystemRoot%\system32\SHELL32.dll,46"
    $Shortcut.Save()
    Write-Log "'Очистить кэш' shortcut... Done!"

    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$StartMenu\Axiom\Axiom 3 Rezerv.lnk")
    $Shortcut.TargetPath = "$ProgFiles\Axiom3\axiom_rezerv.bat"
    $Shortcut.WorkingDirectory = "$ProgFiles\Axiom3\"
    $Shortcut.IconLocation = "%SystemRoot%\system32\SHELL32.dll,244"
    $Shortcut.Save()
    Write-Log "'Axiom 3 Rezerv' shortcut... Done!"

    Write-Log "Creating Registry entry for 'Programs and Features' applet..."

    New-Item -Path $registry -Name "Axiom3" | Out-Null
    New-ItemProperty -Path "$registry\Axiom3" -Name DisplayIcon -Value "$ProgFiles\Axiom3\axiom.exe,0" -Force | Out-Null
    New-ItemProperty -Path "$registry\Axiom3" -Name DisplayName -Value "Axiom 3" -Force | Out-Null
    New-ItemProperty -Path "$registry\Axiom3" -Name InstallLocation -Value "$ProgFiles\Axiom3" -Force | Out-Null
    New-ItemProperty -Path "$registry\Axiom3" -Name Publisher -Value "UIT" -Force | Out-Null
    New-ItemProperty -Path "$registry\Axiom3" -Name UninstallString -Value "$ProgFiles\Axiom3\bin\uninstall.cmd" -Force | Out-Null
    Write-Log "$registry\Axiom3 entry created."
    
    Write-Log "Setting 'Modify' permission on $ProgFiles\Axiom3 folder and nested items...."
    $acl = Get-Acl "$ProgFiles\Axiom3"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($accessRule)
    Set-Acl "$ProgFiles\Axiom3" $acl
    Write-Log "Done!"
}
Catch 
{
    $ErrorMessage = $Error.Exception.Message
    $FailedItem = $Error.Exception.ItemName
    Write-Log @"
$ErrorMessage 
$FailedItem 
"@
}
Finally 
{
    if (Test-Path -Path "$Temp\$OutFile") 
    {
        Remove-Item -Path "$Temp\$OutFile" -Force -ErrorAction SilentlyContinue
    }
}
