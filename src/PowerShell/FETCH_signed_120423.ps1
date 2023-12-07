<#
.SYNOPSIS
FETCH: Flexible Enumeration Tool for Centrally-managed Hosts.

.DESCRIPTION
Author: SpecterOps
Purpose:
  - Collect local sessions, user rights assignments, and group members
  - Stage output for SharpHound collection via centralized management tools
Requirements:
  - Local Administrators group privileges
  - Domain-joined machine with line of sight to domain controller
  - PowerShell 2.0 or higher
  - .NET Framework 3.5 or higher

.PARAMETER DebugMode
Use this switch to enable debug mode.

.PARAMETER LogFilePath
Specifies the path to the log file. Default is 'C:\Windows\CCM\ScriptStore\FetchExecution.log'.

.PARAMETER OutputToShare
Specifies a UNC path to output data. Leave empty to output to a local file or stdout.

.PARAMETER SessionLookbackDays
Number of days to look back for sessions. Default is 7.

.PARAMETER TempDir
Specifies the path for temporary files created to enumerate user rights. Default is $env:TEMP.

.PARAMETER Trace
Enables trace logging for detailed debugging. This will significantly slow down execution.

.PARAMETER Verbose
Enable verbose logging of script execution events.

.PARAMETER WriteTo
Specifies the output file path for results or 'stdout' to write to the console.

.EXAMPLE
.\FETCH.ps1 -Help
# Display help text

.EXAMPLE
.\FETCH.ps1 -SessionLookbackDays 10 -WriteTo C:\Windows\Temp\FetchResults.json
# Collect sessions from the last 10 days of event logs, output to a local file

.EXAMPLE
.\FETCH.ps1 -WriteTo stdout
# Output to stdout

.LINK
https://github.com/BloodHoundAD/SharpHound

#>

[CmdletBinding()]
param(

    [switch]$DebugMode,

    [switch]$Help,

    # Validate that the log file path exists or is set to "none"
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or $_ -eq "none" -or (Test-Path (Split-Path -Path $_))) {
            $true
        } else {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        }
    })]
    [string]$LogFilePath = "C:\Windows\CCM\ScriptStore\FetchExecution.log",

    # Validate that the output directory path is a UNC path if used, ignored if WriteTo is stdout
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) {
            $true
        }
        elseif ($_ -match '^\\\\[^\\]+\\[^\\]+\\?$') {
            if (Test-Path $_) {
                $true
            } else {
                throw "The specified UNC path does not exist: $_"
            }
        } else {
            throw "The output directory path must be a UNC path (e.g., '\\server\share' or '\\server\share\')"
        }
    })]
    [string]$OutputToShare = $null,

    # Number of days behind to fetch sessions
    [ValidateRange(1,365)]
    [int]$SessionLookbackDays = 7,

    # Write temporary files to a specific directory instead of %TEMP%
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or $_ -eq "none" -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$TempDir = $env:TEMP,

    # Enable trace logging for debugging (WARNING: This may take a long time)
    [switch]$Trace,

    # Validate that the output file path exists or is set to "stdout", path ignored if OutputToShare provided
    [ValidateScript({
        if ($_ -eq "stdout" -or ((Test-Path (Split-Path -Path $_)) -and $_ -match '\.json$')) {
            $true
        } elseif (-not (Test-Path (Split-Path -Path $_))) {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        } else {
            throw "Output must be 'stdout' or a local/remote file path ending in '.json'"
        }
    })]
    [string]$WriteTo = "C:\Windows\CCM\ScriptStore\FetchResults.json"
)

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

# Initialize logging
function Write-Log {
    param([string]$Message)
    if ($LogFilePath -ne "none" -and $LogFilePath) {
        # Construct the log message with the current UTC time and write to specified file
        $nowTimeStamp = "$((Get-Date).ToUniversalTime()) UTC"
        $logEntry = "$nowTimeStamp - $Message"
        $logEntry | Out-File -FilePath $LogFilePath -Append
    }
}

# Trace logging - display lines as they are executed
if ($Trace) {
    Set-PSDebug -Trace 1
    Start-Transcript -Path "FetchTrace_$((Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss"))-UTC.log"
    $DebugMode = $true
}

# Debug logging - display variable values
if ($DebugMode) {
    $originalDebugPreference = $DebugPreference
    $DebugPreference = 'Continue'
    #$VerbosePreference = 'Continue'
}

function Write-DebugInfo {
    param([string]$Message)
    Write-Debug "$((Get-Date).ToUniversalTime()) UTC, Line $($MyInvocation.ScriptLineNumber): $Message"
}

function Write-DebugVar {
    param([string]$VariableName)
    Write-Debug "$((Get-Date).ToUniversalTime()) UTC, Line $($MyInvocation.ScriptLineNumber): `$${VariableName} = $(Get-Variable -Name $VariableName -ValueOnly | Out-String)"
}

function Write-VerboseInfo {
    param([string]$Message)
    # Capture in transcript if in debug/trace mode
    if ($DebugMode) {
        Write-DebugInfo $Message
    } else {
        Write-Verbose "$((Get-Date).ToUniversalTime()) UTC, Line $($MyInvocation.ScriptLineNumber): $Message"
        Write-Log $Message
    }
}

Write-VerboseInfo "FETCH execution started"

# Catch and log unexpected execution error messages
try {

    # Confirm this is running on a domain-joined machine
    if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Write-Error "[!] This system is not joined to Active Directory. Exiting."
        exit 1
    }

    # Confirm this is running in a high integrity context
    if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "[!] This script must be executed with administrator privileges. Exiting."
        exit 1
    }

    # Collect local system domain computer account SID via LDAP
    $thisComputerName = $env:COMPUTERNAME
    Write-DebugVar thisComputerName

    $thisComputerDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-DebugVar thisComputerDomain

    $thisComputerDomainAccount = New-Object System.Security.Principal.NTAccount("${thisComputerName}$")
    Write-DebugVar thisComputerDomainAccount

    try {
        $thisComputerDomainSID = $thisComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-DebugVar thisComputerDomainSID
    } catch {
        Write-DebugInfo "Could not translate the domain account to a SID: $sourceComputerDomainAccount"
    }

    # Collect local system FQDN
    $thisComputerFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName
    Write-DebugVar thisComputerFQDN

    # Get the local machine SID prefixed to local accounts
    $thisComputerMachineSID = ((Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object -First 1).SID -replace "-\d+$")
    Write-DebugVar thisComputerMachineSID


    <#
    -------------------------------------------
    Collect sessions
    -------------------------------------------
    #>

    $collectedSessions = @()

    # Function to add or update a session in $collectedSessions
    function AddOrUpdateSessions([ref]$collectedSessions, $newSession) {

        # Check if a session with the same UserSID and ComputerSID already exists
        $existingSession = $collectedSessions.Value | Where-Object { $_.UserSID -eq $newSession.UserSID -and $_.ComputerSID -eq $newSession.ComputerSID }

        if ($existingSession) {

            # If a session with the same UserSID and ComputerSID is found, compare LastSeen times and update if the new one is more recent
            if ($newSession.LastSeen -gt $existingSession.LastSeen) {
                $existingSession.LastSeen = $newSession.LastSeen
            }
            Write-DebugVar existingSession

        } else {
            # If no session with the same UserSID and ComputerSID is found, add the session to the script output
            $collectedSessions.Value += $newSession
            Write-DebugVar newSession
        }
    }

    # Define timespan for session collection
    $sessionLookbackStartDate = (Get-Date).AddDays(-$SessionLookbackDays)
    Write-DebugVar sessionLookbackStartDate

    # Get logged in accounts from HKEY_USERS hive
    $registryKeys = Get-Item -Path "registry::HKEY_USERS\*"
    Write-DebugVar registryKeys

    # Filter keys to those associated with user accounts
    $filteredKeys = $registryKeys | Where-Object {
        $_.Name -match 'S-1-5-21-' -and -not $_.Name.EndsWith('_Classes')
    }
    Write-DebugVar filteredKeys

    foreach ($filteredKey in $filteredKeys) {

        $hkuSID = ($filteredKey.Name -split "\\")[1]
        Write-DebugVar hkuSID

        # Discard local users
        if ($hkuSID -notlike "$thisComputerMachineSID*") {

            # Create a record for each domain user session
            $newSession = @{
                UserSID = $hkuSID
                ComputerSID = $thisComputerDomainSID
                LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f (Get-Date).ToUniversalTime()
            }
            AddOrUpdateSessions ([ref]$collectedSessions) $newSession | Out-Null
        } else {
            Write-DebugInfo "Discarding local user with SID: $hkuSID"
        }
    }

    # Define Event IDs to collect
    $eventIDs = 4624, 4648

    foreach ($eventID in $eventIDs) {
        # Enumerate logon events in the specified window
        $events = Get-WinEvent -FilterHashtable @{Logname='Security';ID=$eventID;StartTime=$sessionLookbackStartDate}

        foreach ($event in $events) {
            $eventXML = [xml]$event.ToXml()
            $eventData = $eventXML.Event.EventData.Data

            switch ($eventID) {

                4624 {
                    Write-DebugVar eventData

                    # Initialize fields to use to filter log data
                    $logonType = $eventData | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
                    Write-DebugVar logonType
                    $sourceIPAddress = $eventData | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
                    Write-DebugVar sourceIPAddress
                    $targetUserSID = $eventData | Where-Object { $_.Name -eq 'TargetUserSid' } | Select-Object -ExpandProperty '#text'
                    Write-DebugVar targetUserSID

                    # Collect domain user logon sessions (discard local users)
                    if ($targetUserSID -like "S-1-5-21-*" -and $targetUserSID -notlike "$thisComputerMachineSID*") {

                        # Collect sessions initiated from remote hosts (Logon Type 3: Network)
                        if ($sourceIPAddress -match "^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$") {

                            # Resolve the source IP address to a hostname, discarding non-terminating errors (failed resolution)
                            $sourceComputerName = $null
                            try {
                                $sourceComputerName = ((nslookup $sourceIPAddress 2>$null | Where-Object { $_ -match '^Name' }) -split ':')[1].Trim()
                                Write-DebugVar sourceComputerName
                            } catch {
                                # Ignore failed DNS lookups
                                Write-DebugInfo "Could not resolve IP to hostname: $sourceIPAddress"
                            }

                            # Translate the hostname to a domain SID
                            if ($sourceComputerName) {
                                $sourceComputerDomainAccount = New-Object System.Security.Principal.NTAccount($sourceComputerName.Split(".")[0] + "$")
                                Write-DebugVar sourceComputerDomainAccount
                            }

                            try {
                                if ($sourceComputerDomainAccount) {
                                    $sourceComputerDomainSID = $sourceComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                    Write-DebugVar sourceComputerDomainSID
                                }
                            } catch {
                                Write-DebugInfo "Could not translate the account to a SID: $sourceComputerDomainAccount"
                            }
                        }
                        elseif ($sourceIPAddress) {
                            Write-DebugInfo "Encountered an event with invalid IpAddress: $sourceIPAddress"
                        }

                        # Collect local logon sessions on this host
                        else {
                            $sourceComputerDomainSID = $thisComputerDomainSID
                            Write-DebugInfo "No source IP address, setting sourceComputerDomainSID to thisComputerDomainSID since this is a local logon"
                        }

                        # If the source IP address (e.g., public IPs) or SID couldn't be resolved, discard the session because we can't tell where it came from
                        if ($null -ne $sourceComputerDomainSID) {

                            # Otherwise, create a record for this domain user session
                            $newSession = @{
                                UserSID = $targetUserSID
                                ComputerSID = $sourceComputerDomainSID
                                LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                            }
                            AddOrUpdateSessions ([ref]$collectedSessions) $newSession | Out-Null

                        } else {
                            Write-DebugInfo "$sourceIPAddress did not look like an IP address"
                        }

                    } else {
                        Write-DebugInfo "$targetUserSID did not match S-1-5-21- or $thisComputerMachineSID"
                    }
                }

                4648 {
                    Write-DebugVar eventData

                    # Initialize fields to use to filter log data
                    $targetUserName = $eventData | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
                    Write-DebugVar targetUserName
                    $targetDomainName = $eventData | Where-Object { $_.Name -eq 'TargetDomainName' } | Select-Object -ExpandProperty '#text'
                    Write-DebugVar targetDomainName

                    # Convert TargetUserName and TargetDomainName to domain SID
                    $targetUserDomainAccount = New-Object System.Security.Principal.NTAccount("$targetDomainName\$targetUserName")
                    Write-DebugVar targetUserDomainAccount

                    try {
                        $targetUserDomainSID = $targetUserDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        Write-DebugVar targetUserDomainSID
                    } catch {
                        Write-DebugInfo "Could not translate the account to a SID: $targetUserDomainAccount"
                    }

                    # Collect domain user logon sessions on this host that did not originate from SYSTEM, discarding local users
                    if ($targetUserDomainSID -like "S-1-5-21-*" -and $targetUserDomainSID -notlike "$thisComputerMachineSID*" -and $targetUserDomainSID -ne $thisComputerDomainSID) {

                        # Create a record for this domain user session
                        $newSession = @{
                            UserSID = $targetUserDomainSID
                            ComputerSID = $thisComputerDomainSID
                            LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                        }
                        AddOrUpdateSessions ([ref]$collectedSessions) $newSession | Out-Null
                    } else {
                        Write-DebugInfo "$targetUserDomainSID did not match S-1-5-21-, started with the local machine SID ($thisComputerMachineSID), or originated from SYSTEM"
                    }
                }
            }
        }
    }
    Write-DebugVar collectedSessions

    $sessions = @{
        "Results" = $collectedSessions
        "Collected" = $true
        "FailureReason" = $null
    }


    <#
    -------------------------------------------
    Collect local user rights assignments
    -------------------------------------------
    #>

    # Export the security configuration to a file, discarding non-terminating errors to prevent stdout pollution
    secedit /export /areas USER_RIGHTS /cfg "$TempDir\secedit.cfg" > $null 2>&1

    # Read the contents of the exported file
    $seceditContents = Get-Content "$TempDir\secedit.cfg" | Out-String
    Write-DebugVar seceditContents

    # Remove the exported file
    Remove-Item "$TempDir\secedit.cfg"

    # Extract and format user rights assignments from the secedit output
    $userRightsLines = $seceditContents -split "`r`n" | Where-Object { $_ -like "SeRemoteInteractiveLogonRight*" }
    Write-DebugVar userRightsLines

    # Initialize output variables
    $userRights = @()

    foreach ($line in $userRightsLines) {
        # Split SIDs from rights assignments
        $lineParts = $line -split "="
        $right = $lineParts[0].Trim()
        # Split SIDs into a list
        $sids = $lineParts[1].Trim() -split ","
        $sids = $sids | ForEach-Object {
            # Remove leading asterisk from each SID
            $sid = $_ -replace "^\*", ""
            # Replace built-in local group SIDs with domain computer SID
            $sid = $sid -replace "S-1-5-32", $thisComputerDomainSID
            @{
                "ObjectIdentifier" = $sid
                "ObjectType" = "LocalGroup"
            }
        }
        $userRight = @{
            "Privilege" = $right
            "Results" = $sids
            "LocalNames" = @()
            "Collected" = $true
            "FailureReason" = $null
        }
        $userRights += $userRight
        Write-DebugVar userRight
    }
    Write-DebugVar userRights


    <#
    -------------------------------------------
    Collect local group memberships
    -------------------------------------------
    #>

    $groups = @()
    $currentGroup = $null

    # Exclude domain controllers from local group collection
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    Write-DebugVar isDC

    if (-not $isDC) {
        # Create an ADSI object for the local computer
        $computer = [ADSI]("WinNT://$env:COMPUTERNAME,computer")
        Write-DebugVar computer

        # Iterate through each child object under the computer (these are local groups and users)
        $groupsObject = $computer.psbase.children | Where-Object { $_.SchemaClassName -eq 'group' }
        Write-DebugVar groupsObject

        foreach ($group in $groupsObject) {
            Write-DebugVar group

            # Retrieve the name of the group
            $groupName = $group.GetType().InvokeMember("Name", 'GetProperty', $null, $group, $null)
            Write-DebugVar groupName

            # Use WMI to fetch group SID
            $groupSID = (Get-WmiObject Win32_Group -Filter "Name='$groupName'").SID
            Write-DebugVar groupSID

            # Output the group name and member SID
            $currentGroup = @{
                # Replace built-in local group SIDs with domain computer SID
                "ObjectIdentifier" = $($groupSID.Replace("S-1-5-32", $thisComputerDomainSID))
                "Name" = $groupName.ToUpper() + "@" + $thisComputerFQDN.ToUpper()
                "Results" = @()
                "LocalNames" = @()
                "Collected" = $true
                "FailureReason" = $null
            }
            Write-DebugVar currentGroup

            # Iterate through each member of the current group
            $members = $group.psbase.Invoke("Members")
            Write-DebugVar members

            foreach ($member in $members) {
                Write-DebugVar member

                # Start with null output
                $result = $null

                # Retrieve the class of the member to ensure it's a User
                $memberClass = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                Write-DebugVar memberClass

                # Retrieve name and SID and convert the SID to human-readable format
                $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                Write-DebugVar memberName
                $memberSIDBytes = $member.GetType().InvokeMember("objectSid", 'GetProperty', $null, $member, $null)
                Write-DebugVar memberSIDBytes
                $memberSID = (New-Object System.Security.Principal.SecurityIdentifier $memberSIDBytes, 0).Value
                Write-DebugVar memberSID

                switch ($memberClass) {

                    "Group" {

                        # Default groups with well-known SIDs
                        if ($memberSID.Length -lt 14) {

                            # Replace built-in local group SIDs with domain computer SID
                            if ($memberSID -like "S-1-5-32-*") {
                                $memberType = "LocalGroup"
                                $result = @{
                                    "ObjectIdentifier" = $($memberSID.Replace("S-1-5-32", $thisComputerDomainSID))
                                    "ObjectType" = $memberType
                                }

                            # Everyone and Authenticated Users include domain users, so collect them
                            } elseif ($memberSID -eq "S-1-1-0" -or $memberSID -eq "S-1-5-11") {
                                $memberType = "Group"
                                $result = @{
                                    "ObjectIdentifier" = "$($thisComputerDomain.ToUpper())-$memberSID"
                                    "ObjectType" = $memberType
                                }

                            } else {
                                Write-DebugInfo "Not collecting members of $memberName ($memberSID)"
                            }

                        # This computer
                        } elseif ($memberSID -eq "$thisComputerMachineSID") {
                            $memberType = "Computer"
                            $result = @{
                                "ObjectIdentifier" = $thisComputerDomainSID
                                "ObjectType" = $memberType
                            }

                        # Non-default local groups
                        } elseif ($memberSID -like "$thisComputerMachineSID*") {
                            $memberType = "LocalGroup"
                            $localGroupID = ($memberSID -split "-")[-1]
                            $result = @{
                                "ObjectIdentifier" = ($thisComputerDomainSID -join $localGroupID)
                                "ObjectType" = $memberType
                            }

                        # Domain groups
                        } else {
                            $memberType = "Group"
                            $result = @{
                                "ObjectIdentifier" = $memberSID
                                "ObjectType" = $memberType
                            }
                        }
                    }

                    "User" {

                        # Skip local users
                        if ($memberSID -notlike "$thisComputerMachineSID*") {

                            # Collect domain users and computers
                            $memberType = "Base"
                            $result = @{
                                "ObjectIdentifier" = $memberSID
                                "ObjectType" = $memberType
                            }
                        }
                    }
                }
                Write-DebugVar result
                if ($result) {
                    $currentGroup["Results"] += $result
                    Write-DebugVar currentGroup
                }
            }
            # Add each local group to script output
            $groups += $currentGroup
        }
    } else {
        Write-DebugInfo "This system is a domain controller, skipping local group membership enumeration"
    }
    Write-DebugVar groups

    <#
    -------------------------------------------
    Format output and stage for SharpHound collection
    -------------------------------------------
    #>

    $data = @(
        @{
            ObjectIdentifier = $thisComputerDomainSID
            Properties = @{
                name = $thisComputerFQDN.ToUpper()
            }
            Sessions = $sessions | Sort-Object -Unique
            UserRights = $userRights
            LocalGroups = $groups
        }
    )
    Write-DebugVar data

    $output = @{
        data = $data
        meta = @{
            methods = 107028
            type = "computers"
            count = $data.Count
            # Version is also replaced by SharpHound before upload to ingest API
            version = 5
        }
    }
    Write-DebugVar output

    # JSON converter for PowerShell 2.0 compatibility
    function ConvertTo-CustomJson {
        param (
            [hashtable] $hash
        )
        $output = ""

        function Convert-Item ($item) {
            if ($item -is [string]) {
                return '"' + $item + '"'
            } elseif ($item -is [int]) {
                return $item
            } elseif ($item -is [bool]) {
                return $item.ToString().ToLower()
            } elseif ($item -is [array]) {
                $arr = @($item | ForEach-Object { Convert-Item $_ })
                return '[' + ($arr -join ",") + ']'
            } elseif ($item -is [hashtable]) {
                $obj = @()
                $item.Keys | ForEach-Object {
                    $key = $_
                    $value = $item[$key]
                    $obj += ('"' + $key + '":' + (Convert-Item $value))
                }
                return '{' + ($obj -join ",") + '}'
            } else {
                return 'null'
            }
        }

        $hash.Keys | ForEach-Object {
            $key = $_
            $value = $hash[$key]
            $output += ('"' + $key + '":' + (Convert-Item $value) + ',')
        }

        # Remove trailing comma and wrap with curly braces
        return '{' + $output.TrimEnd(",") + '}'
    }
    $jsonOutput = ConvertTo-CustomJson $output
    Write-DebugVar jsonOutput

    # Use stdout if specified
    if ($WriteTo -eq "stdout") {
        $jsonOutput
    } else {
    # Use output directory for SMB collection if specified
        if ($OutputToShare) {
            $todaysDirectory = Join-Path -Path $OutputToShare -ChildPath (Get-Date -Format "yyyyMMdd")
            Write-DebugVar todaysDirectory

            # Create a directory for today if it does not already exist
            if (-not (Test-Path $todaysDirectory)) {
                New-Item -Path $todaysDirectory -ItemType Directory
            } else {
                Write-DebugInfo "$todaysDirectory already exists"
            }
            # Use the computer's domain SID in output files written to network shares
            $WriteTo = Join-Path -Path $todaysDirectory -ChildPath "$($thisComputerDomainSID)_$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')).json"
            Write-DebugVar WriteTo
        }
        $jsonOutput | Out-File $WriteTo
    }

} catch {
    Write-DebugInfo "FETCH encountered an error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    Write-Log "FETCH encountered an error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"

} finally {
    # End logging
    Write-VerboseInfo "FETCH execution completed"

    # Restore debug logging preference
    if ($DebugMode) {
        $DebugPreference = $originalDebugPreference
    }

    # Disable trace logging
    if ($Trace) {
        Set-PSDebug -Off
        Stop-Transcript
    }
}
# SIG # Begin signature block
# MIInggYJKoZIhvcNAQcCoIInczCCJ28CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBEO5sCe5NODKAa
# MRWKFY5+fNtYcjkeLevtiW0LUQHDZaCCIQ4wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHTTCCBTWg
# AwIBAgIQBalWtjUPvylwj+Q2s87L8zANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIyMDMzMDAwMDAwMFoXDTI1MDMyOTIzNTk1OVowgbExCzAJBgNVBAYTAlVT
# MREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQWxleGFuZHJpYTEaMBgGA1UE
# ChMRU3BlY3RlciBPcHMsIEluYy4xHjAcBgNVBAsTFUJMT09ESE9VTkQgRU5URVJQ
# UklTRTEaMBgGA1UEAxMRU3BlY3RlciBPcHMsIEluYy4xIjAgBgkqhkiG9w0BCQEW
# E2FidXNlQHNwZWN0ZXJvcHMuaW8wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDd3a1DGe47yqpCqS474OS7pfHXY5YmvzQNnigLHAvaoHjh98vdKwi9RXjd
# wTzqdprnoAVpedhlxL1b8t6t4GDUOlXibE6eeZlEt+KO2Aw2whyp6RdB2q6ZJRPt
# g8QzsXob0olvrJq9N4f0H+N3RxaBxjDoekF7LpSScRwuXIfi+RhTePrfWSsP6f3+
# DxLO0nJ6Kdgoi0KChWOKAYpVNZzRug/leTrrcMff3VpDK1bfVrMGva0TqCVDxiSK
# eeIGlvSBYxh0KdlD8b6uCHeimCJ7CMcqJvGyMCqlloUW5O96l3ETMxK5hfMvfo8Y
# tjrs0FC0VFKizPdi2+BNJXEpYVMQB4jOfYkfZnYWR/PJ0Rv7Kkij0e4a//YWzUp9
# fDBuNeatjlGJEUng4FtJg3jUXU9Erv3UcGO0xdeQVauB+14R0YiTkv31bg5oMevr
# Umfd5f6kOp/4QyIHuzzjg6U/qt7TbfuZwoFILEXTf4LXiUz4l+MpNrG3yUhr3PPl
# IjACVJUCAwEAAaOCAiYwggIiMB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl
# 9E5CMB0GA1UdDgQWBBRhEVbM44gX/mNOxzJVXMIC/DeR9zAeBgNVHREEFzAVgRNh
# YnVzZUBzcGVjdGVyb3BzLmlvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
# BgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQy
# MDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmww
# PgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5k
# aWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JT
# QTQwOTZTSEEzODQyMDIxQ0ExLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEB
# CwUAA4ICAQAcxxQTAeoOW95Y9SUraHBd2riKiu3JMS5uG8lQMhV4HdKnQPR8A/NZ
# vUXifubHwiQq1ppcP8FnkYvjIyU/RjPfkyEnT0RQaPDXqPzCS1EIEp6eNclFhzqJ
# pNk3i9cO0DfazdAVkhOWuT7y43cEaEmENbQ+Ls4Ot+SWiTmEn+iSsM+VQtEaTuQG
# bor9EE8k22D/nuimlngDYs2Vwsz/ey3NyuH4gv4DVG/v1SaotgjFjFCcCuxRxMMY
# u2/YaYVUtuyPUdbQT8kOqFHKuV7QcH+KCFZz7cnfXP8XjPMWMfAjC9GlaZ0Yx7OX
# lcMf3Y1rG8xk5vV5+42G0cec6eMZpBmHO0VtRQfJOFxG+qq2RD17AZs7GZywKnE7
# BFo1fxgJYu4GFwG0ca/qYmTGUARXaDOWpC5BB8SOUI/EgIOb93RYCucrGUdo4+sV
# NbVL0UITjkgN0WQYqTTuZmsKl5goSPfsWD0td9yxWddzUPC4GurjjvwkvwwUtgEA
# h59Qtq9LqrTjNkiWbl3zmEcIiCvhsIn/0QV1N5OrcEJmeLSvo7N8kW5ysTxKkxLb
# XJFUpmlWdO6Lbq4r+0Fbtxdz27pwJNXaynEZOLrlg8H3D1s0TPGXRq7uMpHj1dHJ
# AfTXj9jg1b19XSA/fyA91C8rB1wATR6pqT8C+9yPqNJyKlldrVOvfjGCBcowggXG
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2
# IFNIQTM4NCAyMDIxIENBMQIQBalWtjUPvylwj+Q2s87L8zANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAD
# 0tBBnriwHYeP+YEz9gTcDVJJteMlJrcDW1btBpS58TANBgkqhkiG9w0BAQEFAASC
# AYCOM9A9/AavkH5YMhDxg0VizN/ZzB3uQAYPNH+52QmR530d4vbBMiBk8HrvtTQx
# b5Gbk1JZN8LV0sAsPcBSj5Rk7dZ8hR+je6kTBZe3q1+XLCB0eoSG69NfG6RmZT82
# BVIy9uALCBbXGPF6Nly7q/VUDbXDAv6ItYsWX8F6TNpeA3eXn0qhkGj3AtyVDuB+
# go+QyscHrPJ1iETv7mTSzBuBFkCbnAUL1oPirb3TLx7rIHTeGQ536jpvdHoa/uPH
# qLjNRebTV975RXIKCLe8l8U5/9SRBxo4z3mEDD/ChIyniMV0fzhBq4cE2XMo7lQb
# 4ssmOCHTN9HIGbnCXuPgLXokPHweweajZ72YqArQ0+5sCxQNBPifp+Jl4ovSbM6A
# CWe/xvpzxI9fon6QMNjM1p33zM3bkRajxn+ds5w/SNOSvkMPqhUxvXB55jt8GZlB
# c5XqyBDum2nesujnJGj3UUpXzXpucki44HVjaEZPsQcrgXyjSF120REaMFzqUDU2
# 0W+hggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/zlJ0I
# Oaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMxMjA1MDAwMjIzWjAvBgkqhkiG9w0BCQQx
# IgQgaHjqZgjfAyen6FC/Cq0vQ6zIJVwc1Ypiwx2CLzJ06R4wDQYJKoZIhvcNAQEB
# BQAEggIAW5HLq2b5x7WM8StKj97L5rd04JXdk4gnag0W/kzq2ohQdu9KED/Q9T9i
# DkEHtyMYdfbMJntx1ZCL6WOhZHMCThg0frqxnoXMkJXhwNQuzG3brCDC7yZdQ5K6
# olW3Ij0gjLS+CdmsLs8kaP5vVY9cMnDNPxztfHMeKPcMR/iwGHApyH130t4wdINJ
# ZoP7c1rmysZLvjUbJ2vxgK764a4QMckZYkfsUXrcYKkFS+7ApjuZ4g8VAXkuAJGi
# t3BEZQ0T8D8Pfpg3toYanRcgfyZjwzvAwlPpai0a21jD+JGJnV5BD7Y2sA5h9wTT
# usXZUvCz3RRDZk4ytQB9anQWnOYjdZx6LcXp4auOLp9a5rBfDqEmf9nXsDJ3TNt7
# Yx0oosOKQXwNbmWtsXw5AoIHQh1cpwk6hIyZnDwjQkbrcqlu3oYVmph102hTWnCq
# OX112zHCUmJbbRp41WwP2f92CWW5DM8sNmleHiEdXNeJxqPqee8rXpkV5BKekcAv
# 6FALaV5z9Q6vR8PGSvGzxa7bo3GZD3uaPZxbTskgvWxoPyLBiOGluGt7AVLq5fbu
# fpMhhcsudz17lXH7Ll4GaqYI5wr02iv3APz1rCjnFgxxNmJvk5t8lttQmkKIjCGm
# 3NzQKeJmZRdvGDfBlqo/hLTtPCO1VIGaAD+fpFyJNGr96oTkeKc=
# SIG # End signature block
