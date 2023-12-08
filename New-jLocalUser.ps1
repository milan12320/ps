function New-jLocalUser1 {
<#
.SYNOPSIS
    Creates Local User and adds it to Users Local group.
        
.DESCRIPTION
    Creates local user account with predefined properties -AccountNeverExpires, -PasswordNeverExpires, -UserMayNotChangePassword on local or remote PC from file .CSV or manually entering user name.
    Checks if username exists already.
    Adds newly created account to Users group.
    Requires entering local admin password if connects to remote PC.
    For remote PC use User PowerShell session in MeshCentral.
    For Localhost use Admin Powershell

.EXAMPLE
    PS D:\> New-jLocalUser -Name qwerty -ComputerName pc4,pc5
    Enter password for tmp:
    ***
    Enter password for jentyadmin:
    ************

    ПРЕДУПРЕЖДЕНИЕ: [pc5] is not found
    Name   Enabled PSComputerName
    ----   ------- --------------
    tmp    True pc4

    
    PS D:\>

.EXAMPLE
    Reads remote PC names from file D:\comp.txt, connects and creates Local user temp.
    Format D:\comp.txt - one name in a row:
       pc4
       pc5
       pc6 

    PS D:\> Get-Content -Path .\comp.txt | New-jLocalUser -Name temp

.EXAMPLE
    PS D:\> New-jLocalUser -Name temp -ComputerName (Get-Content -Path .\comp.txt)

.INPUTS
    $Name or $Path - user name or literal path to file .CSV 
    $ComputerName - one or more PC names as string (NETBIOS name, FQDN or IP address).
.OUTPUTS
    [System.Array]  -array of [LocalUser] objects       
#>

[CmdletBinding(DefaultParameterSetName='CSV')]
[OutputType([Array])]
Param (
       [Parameter(Mandatory,Position=0, ParameterSetName='string')]
       [ValidateLength(1,20)]
       [ValidatePattern("^[a-zA-Z0-9\s\%\#\$\&\.]+$")]
       [string[]]$Name,
       [Parameter(Mandatory, ParameterSetName='CSV')]
       [ValidateScript({Test-Path -Path $_ })]
       [ValidateScript({$_ -match ".csv"})]
       [string]$Path,
       [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$true)]
       [string[]]$ComputerName='localhost',
       [Parameter(Mandatory=$false,Position=2)]
       [ValidateNotNullorEmpty()]
       [string]$Admin='jentyadmin'
)   
    begin {
        function Export-jCSV {
        <#
            .SYNOPSIS
                Exports user names and passwords from file .CSV.
        
	        .DESCRIPTION
                Exports user names and passwords from file .CSV to array of PSCustomObjects ([string]Name, [SecureString]Credentials)
                Creates PSCustomObject with properties Name and Credentials for each CSV row (user).
                Does not check validity if usernames and passwords.
            .PARAMETER Name
                 [string]$Path, valid full path to file .CSV
                          
            .EXAMPLE
                PS D:\> Export-jCSV -Path D:\users.csv
                Name                   Credentials
                ----                   -----------
                temp  System.Security.SecureString
                temp1 System.Security.SecureString
        
                Format of users.csv:   UserName,Password
                                       temp,12345
                                       temp1,123456
            .EXAMPLE   
                PS D:\> Get-ChildItem 'D:\users.csv' | Export-jCSVn

                Name                   Credentials
                ----                   -----------
                temp  System.Security.SecureString
                temp1 System.Security.SecureString

            .INPUTS
                [System.String]

            .OUTPUTS
                [System.Array] -Array of [LocalUser] objects

        #>
        
        [CmdletBinding()]
        Param (
            [Parameter(Position=0, Mandatory, ValueFromPipeline=$true)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({Test-Path -Path $_ })]
            [ValidateScript({$_ -match ".csv"})]
            [string]$Path
        )   
        begin {
            $rows = @()
            Write-Verbose 'Empty array of rows objects from .CVS $rows created'
        }
        process {
            Try {
                Write-Verbose 'Importing file .CSV to $CsvTable'
                $CsvTable = Import-Csv -Path $Path -ErrorAction Stop
                for ($i = 0; $i -lt $CsvTable.Count; $i++){
                    $user=$CsvTable[$i].UserName
                    $passwd = $CsvTable[$i].Password
                    $secPass = ConvertTo-SecureString -String $passwd -AsPlainText -Force -ErrorAction Stop
                    $rows += [PSCustomObject]@{Name=$user; Credentials=$secPass}
                    Write-Verbose "Object [row $i] added to array [rows]"
                }
            }
            Catch {
                Write-Warning -Message @"
$($error[0].Exception.Message)
$($error[0].CategoryInfo)
Line: $($error[0].Exception.Line)
"@
            }
        }
        End {
            return $rows
        }
    }
        function Get-jCredential1 {
            [CmdletBinding()]
            [OutputType([Array])] #array of [PSCredential] objects
            Param (
                [Parameter(Mandatory, Position=0)]
                [ValidateNotNullorEmpty()]
                [string[]]$Name,
                [Parameter(Mandatory=$false, Position=1)]
                [ValidateNotNullorEmpty()]
                [string]$Admin='jentyadmin'
            )   
            $Credentials = @()
            for ($i=0;$i -lt $Name.Count; $i++){
                if ($Name[$i] -notmatch $Admin) {
                    Do {    
                        Write-Host "Enter password for $($Name[$i]):" -ForegroundColor Cyan
                        $SecureString1=Read-Host -AsSecureString
                        Write-Host "Confirm password for $($Name[$i]):" -ForegroundColor Yellow
                        $SecureString2=read-host -assecurestring
                        $cred1 = New-Object System.Management.Automation.PSCredential($Name[$i],$SecureString1)
                        $cred2 = New-Object System.Management.Automation.PSCredential($Name[$i],$SecureString2)
                        $pass1 = $cred1.GetNetworkCredential().password 
                        $pass2 = $cred2.GetNetworkCredential().password
                        if ( $pass1 -ne $pass2) {
                            Write-Warning " Password is not confirmed!"
                        }        
                    }     
                    Until ( $pass1 -eq $pass2)
                    $Credentials+= $cred1
                }
                else {
                    Write-Host "Enter password for $($Name[$i]):" -ForegroundColor Cyan
                    $SecureString=Read-Host -AsSecureString
                    $Credentials+=New-Object System.Management.Automation.PSCredential($Name[$i],$SecureString)
                }
            }
            Return $Credentials
        }
        function New-jUser {
        [CmdletBinding()]
        [OutputType([Array])]
        Param (
            [Parameter(Mandatory,Position=0,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullorEmpty()]
            [string[]]$Name,
            [Parameter(Mandatory,Position=1,ValueFromPipelineByPropertyName=$true)]
            [SecureString[]]$Credentials
        )   
        begin {
            $LocalUsers=@()
        }
        process {
            for ($i=0;$i -lt $Name.Count;$i++) {
                if ((Get-LocalUser -Name $Name[$i] -ErrorAction SilentlyContinue) -eq $null) {           
                        $LocalUser=New-LocalUser -AccountNeverExpires -Name $Name[$i] -Password $Credentials[$i] -PasswordNeverExpires -UserMayNotChangePassword
                        Add-LocalGroupMember -Name 'Users' -Member $Name[$i]
                        $LocalUsers+=$LocalUser
                }
                else {
                    Write-Warning ["$env:COMPUTERNAME\$($Name[$i])] already exists."
                }
            }
            "======================================="
        }
        End {
            Return $LocalUsers
        }
}        
        function Test-jConnection {
        [CmdletBinding()]
        [OutputType([boolean])]
        Param (
            [Parameter(Mandatory, Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$ComputerName
        )   
            if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
                if (Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue) {
                    Return $true
                }
                else {
                    Write-Warning "[$ComputerName] does not accept WinRM query"
                    Return $false
                }
            }
            else {
                Write-Warning "[$ComputerName] is not found"
                Return $false
            }
        }
                
        $NewLocalUsers = @()
        #Checking if ParamemterSet ='string'
        if ($PsCmdlet.ParameterSetName -eq 'string') {
                 $Credentials=(Get-jCredential1 -Name $Name -Admin $Admin).Password
        }
        else {
            $csv=Export-jCSV -Path $Path
            $Name=$csv.Name
            $Credentials=$csv.Credentials
        }
        # if expecting data from pipeline for -ComputerName parameter or -ComputerName is an array of PC names get admin credentials for Invoke-Command and go to Process Block. 
        if (($PSCmdlet.MyInvocation.ExpectingInput) -or ($ComputerName -notmatch 'localhost')) {
            $AdminCredential=Get-jCredential1 -Name $Admin -Admin $Admin
        }
    }
    process {    
        if ($ComputerName -eq 'localhost') {
            $NewLocalUsers+=New-jUser -Name $Name -Credentials $Credentials
        }
        else {
            foreach ($cn in $ComputerName) {
                if (Test-jConnection -ComputerName $cn) {
                    $NewLocalUsers+=Invoke-Command -ComputerName $cn -Credential $AdminCredential -ScriptBlock ${function:New-jUser} -ArgumentList $Name,$Credentials
                }
            }
        }
    }
    end {
        return $NewLocalUsers
    }
}
