function Test-Subnet {
<#
         .SYNOPSIS
         Scans subnet and displays live hosts IP addresses.
        .DESCRIPTION
         Scans Subnet that is provided by "Subnet" parameter in range of addresses provided by "Range" parameter by pinging IP addresses, then displays live hosts.
        .PARAMETER <Subnet>
         format: xxx.xxx.xxx.0
        .PARAMETER <Range>
         format: (x..x) as a PowerShell range operator 
                  
        .EXAMPLE
         PS D:\> .\Test-Subnet.ps1 -Subnet 150.0.0.0 -Range (1..5)
         150.0.0.4
         150.0.0.5
#>
[cmdletbinding()]
Param (
    [Parameter(Position=0, Mandatory=$true, HelpMessage="Enter a string representing subnet. Example: 191.168.1.0")]
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
    [string]$Subnet,
    [Parameter(Position=1)]
    [ValidateRange(1,254)]
    [string[]]$Range=(1..10)
)

    $GivenIpAddessrList=[System.Collections.ArrayList]@()
    ForEach ($r in $Range) {
        $IpAddr=([regex]"0$").replace($Subnet,$r)
        $GivenIpAddessrList+=$IpAddr
    }
    $job=Test-Connection -ComputerName $GivenIpAddessrList -Count 1 -AsJob
    $result=Receive-Job -Job $job -Wait
    $LiveIpAddressList=$result | where {$_.StatusCode -eq 0} |select -ExpandProperty Address |Sort-Object -Property {[System.Version]$_}
    Remove-Job -Job $job
    $LiveIpAddressList
}