#Requires -Version 3.0
#Requires -Modules ActiveDirectory
Function Find-WhereUserIsLoggedIn {
    [CmdletBinding(DefaultParameterSetName='Prefix')]
    param(
        [Parameter(
            Position=0,
            Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$False,
            HelpMessage="`n[H] Enter the SamAccountName of the user you are looking for. `n[E] EXAMPLE: john.wick")]
        [String]$Username,

        [Parameter(
            ParameterSetName='Prefix',
            Position=1,
            Mandatory=$True,
            ValueFromPipeline=$False,
            HelpMessage="`n[H] Enter the naming prefix of computers you are checking the user is logged into. `n[E] EXAMPLE: DESKTOPS-*")]
        [SupportsWildcards()]
        [String]$Prefix,

        [Parameter(
            ParameterSetName='Computers',
            Position=1,
            Mandatory=$True,
            ValueFromPipeline=$False,
            HelpMessage="`n[H] Enter the names of computers you wish to check on where a user is logged into. `n[E] EXAMPLE: DC01.domain.com, DHCP.domain.com, DNS.domain.com")]
        [String[]]$ComputerName
    )  # End param

    BEGIN {

        Import-Module -Name ActiveDirectory -ErrorAction Stop
        $Obj = New-Object -TypeName System.Collections.ArrayList
        Try {
            $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Domain = $DomainObj.Name
        } Catch {
            Write-Output -InputObject "[x] Failed Getting Current Domain"
            Write-Output -InputObject $_
            Return
        }  # End Try Catch

        $Username = $Username.Replace("@$Domain","")
        Write-Verbose -Message "[*] Ensuring Commands Are Executed On A Domain Controller"
        If ("$env:COMPUTERNAME.$Domain" -notin $DomainObj.DomainControllers.Name) {
            Throw "[x] This cmdlet only works when executed on a domain controller"
        }  # End If

    } PROCESS {

        Switch ($PSCmdlet.ParameterSetName) {

            'Prefix' {

                Write-Verbose -Message "[*] Building List Of Possible Computers Using The Pattern: $Prefix"
                $CutOffDate = (Get-Date).AddDays(-60)
                Try {

                    $ComputerNames = Get-ADComputer -Properties Name,DNSHostName,SamAccountName,Enabled,LastLogonDate -Filter {
                            LastLogonDate -gt $CutOffDate -and
                            Enabled -eq $True
                        } | Where-Object -FilterScript {
                            $_.SamAccountName -like $Prefix
                        }  # End Where-Object

                } Catch {
                    Write-Output -InputObject "[x] Failed Getting Computers From Active Directory"
                    Write-Output -InputObject $_
                    Return
                }  # End Try Catch

                Write-Verbose -Message "[*] Searching For $Username On Computers That Match $Prefix"
                ForEach ($Computer in $ComputerNames) {

                    $CimSession = $Null
                    Try {

                        If (!($Computer.DNSHostName)) {
                            Write-Verbose -Message "[*] Skipping $($Computer.Name) Because DNSHostName Is Empty"
                            Continue
                        }  # End If

                        $CimSession = New-CimSession -ComputerName $Computer.DNSHostName -SessionOption (New-CimSessionOption -UseSsl) -ErrorAction Stop
                        $CIM = Get-CimInstance -ClassName Win32_Process -CimSession $CimSession -Filter "Name = 'explorer.exe'" -ErrorAction Stop
                        If ($CIM) {

                            $ProcessOwner = Invoke-CimMethod -InputObject $CIM -MethodName GetOwner -ErrorAction SilentlyContinue
                            If ($ProcessOwner.User -eq $Username) {

                                Write-Output -InputObject "[*] $Username is logged in on $($Computer.Name)"
                                [Void]$Obj.Add(
                                    [PSCustomObject]@{
                                        User    = $Username
                                        Devices = $Computer.Name
                                    }
                                )
                            }  # End If
                        }  # End If

                    } Catch {
                        Write-Verbose -Message "[*] Unable To Query $($Computer.Name)"
                    } Finally {
                        If ($CimSession) {
                            Remove-CimSession -CimSession $CimSession -ErrorAction SilentlyContinue
                        }  # End If
                        Clear-Variable -Name ProcessOwner,CIM,CimSession -ErrorAction SilentlyContinue
                    }  # End Try Catch Finally

                }  # End ForEach

            }  # End Switch Prefix

            'Computers' {

                Write-Verbose -Message "[*] Searching For $Username On $ComputerName"
                ForEach ($Computer in $ComputerName) {

                    $CimSession = $Null
                    Try {

                        $CimSession = New-CimSession -ComputerName $Computer -SessionOption (New-CimSessionOption -UseSsl) -ErrorAction Stop
                        $CIM = Get-CimInstance -ClassName Win32_Process -CimSession $CimSession -Filter "Name = 'explorer.exe'" -ErrorAction Stop
                        If ($CIM) {
                            $ProcessOwner = Invoke-CimMethod -InputObject $CIM -MethodName GetOwner -ErrorAction SilentlyContinue

                            If ($ProcessOwner.User -eq $Username) {
                                Write-Output -InputObject "[*] $Username is logged in on $Computer"
                                [Void]$Obj.Add(
                                    [PSCustomObject]@{
                                        User    = $Username
                                        Devices = $Computer
                                    }
                                )
                            }  # End If
                        }  # End If

                    } Catch {
                        Write-Verbose -Message "[*] Unable To Query $Computer"
                    } Finally {
                        If ($CimSession) {
                            Remove-CimSession -CimSession $CimSession -ErrorAction SilentlyContinue
                        }  # End If
                        Clear-Variable -Name ProcessOwner,CIM,CimSession -ErrorAction SilentlyContinue
                    }  # End Try Catch Finally
                }  # End ForEach
            }  # End Switch Computers
        }  # End Switch

    } END {
        Write-Output -InputObject "[*] Search Completed"
        Write-Output -InputObject $Obj
    }  # End END

}  # End Function Find-WhereUserIsLoggedIn
