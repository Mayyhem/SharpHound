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
    secedit /export /areas USER_RIGHTS /cfg "C:\Windows\Temp\secedit.cfg" > $null 2>&1

    # Read the contents of the exported file
    $seceditContents = Get-Content "C:\Windows\Temp\secedit.cfg" | Out-String
    Write-DebugVar seceditContents

    # Remove the exported file
    Remove-Item "C:\Windows\Temp\secedit.cfg"

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