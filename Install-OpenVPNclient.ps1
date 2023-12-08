[CmdletBinding()]
Param ()
$software = "OpenVPN client"
$url = "http://wsus.jenty.by/upd/ovpn.zip"
$version = "2.6.601"
$MSI = "OpenVPN-2.6.6-I001-amd64.msi"
$Temp = "C:\Windows\Temp"
$OutFile = "ovpn.zip"
$OutFilePath = "$Temp\ovpn"
$Log = "$Temp\InstallOVPNClient.log"
$registry ="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"

function Write-Log {
    Out-File -FilePath $log -InputObject "$(Get-Date -Format "dd/MM/yyyy HH:mm:ss")  $($args[0])" -Encoding default -Append
}

Write-Verbose "For Win8: turn on TLS 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Verbose "Check if software is installed testing Uninstall regkey"

$IsInstalled = Get-ItemProperty -Path $registry | Where-Object {$_.DisplayName -like "OpenVPN*"} 
 
Try {
        $InstalledVersion = $IsInstalled | Where-Object {$_.DisplayVersion -like '*.*.*'} |
                                                select -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue
       
        $MsiArgumentList = "/i $OutFilePath\$MSI ADDLOCAL=OpenVPN.Service,OpenVPN.GUI,OpenVPN,Drivers,Drivers.TAPWindows6 /passive"
        if ($InstalledVersion -eq $version ) {
            Write-Log "$software $version is already installed."
        }
        elseif (($InstalledVersion -lt $version) -or (! $InstalledVersion) ) {
            Write-Log "$software $InstalledVersion is installed."
            Write-Log "Downloading latest version from $url"
            Invoke-WebRequest -Uri $url -OutFile $Temp\$OutFile -ErrorAction Stop
            Write-Log "Unzipping to $OutFilePath"
            Expand-Archive -Path $Temp\$OutFile -DestinationPath $Temp
            Write-Log "Installing $MSI..."
            $return = Start-Process msiexec -ArgumentList $MsiArgumentList -Wait -PassThru -ErrorAction Stop
            If (@(0,3010) -contains $return.exitcode) {
                Write-Log "$software $version is installed successfully."
            }
            else {
                Write-Log "Something went wrong...$software $version is not installed. Exit Code is $($return.ExitCode)"
            }
            Copy-Item -Path $OutFilePath\Jenty.ovpn -Destination 'C:\Program Files\OpenVPN\config\' -Force
            Write-Log "Client configuration file Jenty.ovpn copied to C:\Program Files\OpenVPN\config\"
        }
}
Catch {
    $ErrorMessage = $Error.Exception.Message
    $FailedItem = $Error.Exception.ItemName
    Write-Log @"
$ErrorMessage 
$FailedItem 
"@
}

Finally {
    if (Test-Path -Path $OutFilePath) {
        Remove-Item -Path $OutFilePath -Recurse -Force
        Remove-Item -Path $Temp\$OutFile -Force
        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OpenVPN\Utilities" -Recurse -Force
        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OpenVPN\Shortcuts" -Recurse -Force
        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OpenVPN\Documentation" -Recurse -Force
    }
}
