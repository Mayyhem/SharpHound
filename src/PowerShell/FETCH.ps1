﻿<#
-------------------------------------------
FETCH: Flexible Enumeration Tool for Centrally-managed Hosts

Author: SpecterOps
Purpose:
  - Collect local sessions, user rights assignments, and group members
  - Stage output for SharpHound collection via centralized management tools
Requirements:
  - Local Administrators group privileges
  - Domain-joined machine with line of sight to domain controller
  - PowerShell v2 or higher
  - .NET Framework 3.5 or higher

-------------------------------------------
#>

[CmdletBinding()]
param(
    # Validate that the log file path exists or is set to "none"
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or $_ -eq "none" -or (Test-Path (Split-Path -Path $_))) {
            $true
        } else {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        }
    })]
    [string]$logFilePath = "C:\Windows\CCM\ScriptStore\FetchExecution.log",

    # Validate that the output directory path is a UNC path if used, ignored if writeTo is stdout
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
    [string]$outputToShare = $null,

    # Number of days behind to fetch sessions
    [ValidateRange(1,365)]
    [int]$sessionLookbackDays = 7, 

    # Validate that the output file path exists or is set to "stdout", path ignored if outputToShare provided
    [ValidateScript({
        if ($_ -eq "stdout" -or ((Test-Path (Split-Path -Path $_)) -and $_ -match '\.json$')) {
            $true
        } elseif (-not (Test-Path (Split-Path -Path $_))) {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        } else {
            throw "Output must be 'stdout' or a local/remote file path ending in '.json'"
        }
    })]
    [string]$writeTo = "C:\Windows\CCM\ScriptStore\FetchResults.json"
)

# Enable/disable trace logging 
#Set-PSDebug -Trace 1

# If there are undefined parameters, throw an error
$definedParams = @("logFilePath", "outputToShare", "sessionLookbackDays", "writeTo")
$undefinedParams = $PSBoundParameters.Keys | Where-Object { -not ($definedParams -contains $_) }

if ($undefinedParams -ne $null -and $undefinedParams.Count -gt 0) {
    throw "Undefined parameters: $($undefinedParams -join ', ')"
}

# Initialize logging
if ($logFilePath -ne "none") {
    $nowTimeStamp = (Get-Date).ToUniversalTime()
    "$nowTimeStamp UTC - FETCH execution started" | Out-File -FilePath $logFilePath -Append
    }

# Catch and log execution error messages
try {
    # Confirm this is running on a domain-joined machine
    if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Write-Host "[!] This system is not joined to Active Directory. Exiting."
        if ($logFilePath -ne "none") {
            "$((Get-Date).ToUniversalTime()) UTC - Exiting because this system is not AD-joined" | Out-File -FilePath $logFilePath -Append
        } 
        exit
    }
    # Confirm this is running in a high integrity context
    if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 
        Write-Host "[!] This script must be executed with administrator privileges. Exiting."
        if ($logFilePath -ne "none") {
            "$((Get-Date).ToUniversalTime()) UTC - Exiting because the script was not executed in a high integrity context" | Out-File -FilePath $logFilePath -Append
        } 
        exit
    }

    # Collect local system domain computer account SID via LDAP
    $thisComputerName = $env:COMPUTERNAME
    $thisComputerDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    $thisComputerDomainAccount = New-Object System.Security.Principal.NTAccount("${thisComputerName}$")

    try {
        $thisComputerDomainSID = $thisComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value   
    } catch {
        if ($logFilePath -ne "none") {
            "$((Get-Date).ToUniversalTime()) UTC - Could not translate the domain account to a SID: $sourceComputerDomainAccount" | Out-File -FilePath $logFilePath -Append
        } 
    }

    # Collect local system FQDN
    $thisComputerFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName

    # Get the local machine SID prefixed to local accounts
    $thisComputerMachineSID = ((Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object -First 1).SID -replace "-\d+$")


    <#
    -------------------------------------------
    Collect sessions
    -------------------------------------------
    #>

    $collectedSessions = @()

    # Function to add or update a session in $collectedSessions
    function AddOrUpdateSessions($collectedSessions, $newSession) {
        # Check if a session with the same UserSID and ComputerSID already exists
        $existingSession = $collectedSessions | Where-Object { $_.UserSID -eq $newSession.UserSID -and $_.ComputerSID -eq $newSession.ComputerSID }

        if ($existingSession) {
            # If a session with the same UserSID and ComputerSID is found, compare LastSeen times and update if the new one is more recent
            if ($newSession.LastSeen -gt $existingSession.LastSeen) {
                $existingSession.LastSeen = $newSession.LastSeen
            }
        } else {
            # If no session with the same UserSID and ComputerSID is found, add the session to the script output
            $collectedSessions += $newSession
        }
        return $collectedSessions
    }

    # Define timespan for session collection
    $sessionLookbackStartDate = (Get-Date).AddDays(-$sessionLookbackDays)

    # Get logged in accounts from HKEY_USERS hive
    $registryKeys = Get-Item -Path "registry::HKEY_USERS\*"

    # Filter keys to those associated with user accounts
    $filteredKeys = $registryKeys | Where-Object {
        $_.Name -match 'S-1-5-21-' -and -not $_.Name.EndsWith('_Classes')
    }

    foreach ($filteredKey in $filteredKeys) {

        $hkuSID = ($filteredKey.Name -split "\\")[1]

        # Discard local users
        if ($hkuSID -notlike "$thisComputerMachineSID*") {
            
            # Create a record for each domain user session
            $newSession = @{
                UserSID = $hkuSID
                ComputerSID = $thisComputerDomainSID
                LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f (Get-Date).ToUniversalTime()
            }
            $collectedSessions = AddOrUpdateSessions $collectedSessions $newSession
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
                    # Initialize fields to use to filter log data
                    $logonType = $eventData | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
                    $sourceIPAddress = $eventData | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
                    $targetUserSID = $eventData | Where-Object { $_.Name -eq 'TargetUserSid' } | Select-Object -ExpandProperty '#text'
                    
                    # Collect domain user logon sessions (discard local users)
                    if ($targetUserSID -like "S-1-5-21-*" -and $targetUserSID -notlike "$thisComputerMachineSID*") {
                       
                        # Collect sessions initiated from remote hosts (Logon Type 3: Network)
                        if ($sourceIPAddress -match "^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$") {
                            # Resolve the source IP address to a hostname, discarding non-terminating errors (failed resolution)
                            #$sourceComputerName = Resolve-DnsName -Name $sourceIPAddress -Type PTR 2>$null
                            $sourceComputerName = $null
                            try {
                                $sourceComputerName = ((nslookup $sourceIPAddress 2>$null | Where-Object { $_ -match '^Name' }) -split ':')[1].Trim()
                            } catch {
                                # Ignore failed DNS lookups
                                if ($logFilePath -ne "none") {
                                    "$((Get-Date).ToUniversalTime()) UTC - Could not resolve IP to hostname: $sourceIPAddress" | Out-File -FilePath $logFilePath -Append
                                }
                            }

                            # Translate the hostname to a domain SID
                            if ($sourceComputerName) {
                                $sourceComputerDomainAccount = New-Object System.Security.Principal.NTAccount($sourceComputerName.Split(".")[0] + "$")
                            }

                            try {
                                if ($sourceComputerDomainAccount) {
                                    $sourceComputerDomainSID = $sourceComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                }
                            } catch {
                                if ($logFilePath -ne "none") {
                                    "$((Get-Date).ToUniversalTime()) UTC - Could not translate the account to a SID: $sourceComputerDomainAccount" | Out-File -FilePath $logFilePath -Append
                                }
                            }
                        }
                        elseif ($sourceIPAddress) {
                            if ($logFilePath -ne "none") {
                                "$((Get-Date).ToUniversalTime()) UTC - Encountered an event with invalid IpAddress: $sourceIPAddress" | Out-File -FilePath $logFilePath -Append
                            }
                        }

                        # Collect local logon sessions on this host
                        else {
                            $sourceComputerDomainSID = $thisComputerDomainSID
                        }
                        
                        # If the source IP address couldn't be resolved, for example public IP addresses, discard the session because we can't tell where it came from
                        if ($sourceComputerDomainSID -ne $null) {
                            
                            # Otherwise, create a record for this domain user session
                            $newSession = @{
                                UserSID = $targetUserSID
                                ComputerSID = $sourceComputerDomainSID
                                LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                            }
                            $collectedSessions = AddOrUpdateSessions $collectedSessions $newSession
                        }
                    }
                }

                4648 {
                    # Initialize fields to use to filter log data
                    $targetUserName = $eventData | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
                    $targetDomainName = $eventData | Where-Object { $_.Name -eq 'TargetDomainName' } | Select-Object -ExpandProperty '#text'

                    # Convert TargetUserName and TargetDomainName to domain SID
                    $targetUserDomainAccount = New-Object System.Security.Principal.NTAccount("$targetDomainName\$targetUserName")
                    
                    try {
                        $targetUserDomainSID = $targetUserDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        if ($logFilePath -ne "none") {
                            "$((Get-Date).ToUniversalTime()) UTC - Could not translate the account to a SID: $targetUserDomainAccount" | Out-File -FilePath $logFilePath -Append
                        } 
                    }

                    # Collect domain user logon sessions on this host that did not originate from SYSTEM, discarding local users
                    if ($targetUserDomainSID -like "S-1-5-21-*" -and $targetUserDomainSID -notlike "$thisComputerMachineSID*" -and $targetUserDomainSID -ne $thisComputerDomainSID) {
                        
                        # Create a record for this domain user session
                        $newSession = @{
                            UserSID = $targetUserDomainSID
                            ComputerSID = $thisComputerDomainSID
                            LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                        }
                        $collectedSessions = AddOrUpdateSessions $collectedSessions $newSession
                    }
                }
            }
        }
    }
    
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

    # Remove the exported file
    Remove-Item "C:\Windows\Temp\secedit.cfg"

    # Extract and format user rights assignments from the secedit output
    $userRightsLines = $seceditContents -split "`r`n" | Where-Object { $_ -like "SeRemoteInteractiveLogonRight*" }

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
    }


    <#
    -------------------------------------------
    Collect local group memberships
    -------------------------------------------
    #>
 
    $groups = @()
    $currentGroup = $null

    # Exclude domain controllers from local group collection
    $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4

    if (-not $isDC) {
        # Create an ADSI object for the local computer
        $computer = [ADSI]("WinNT://$env:COMPUTERNAME,computer")

        # Iterate through each child object under the computer (these are local groups and users)
        $groupsObject = $computer.psbase.children | Where-Object { $_.SchemaClassName -eq 'group' }

        foreach ($group in $groupsObject) {

            # Retrieve the name of the group
            $groupName = $group.GetType().InvokeMember("Name", 'GetProperty', $null, $group, $null)

            # Use WMI to fetch group SID
            $groupSID = (Get-WmiObject Win32_Group -Filter "Name='$groupName'").SID

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

            # Iterate through each member of the current group
            $members = $group.psbase.Invoke("Members")

            foreach ($member in $members) {

                # Start with null output
                $result = $null
                
                # Retrieve the class of the member to ensure it's a User
                $memberClass = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)

                # Retrieve name and SID and convert the SID to human-readable format
                $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null) 
                $memberSIDBytes = $member.GetType().InvokeMember("objectSid", 'GetProperty', $null, $member, $null)
                $memberSID = (New-Object System.Security.Principal.SecurityIdentifier $memberSIDBytes, 0).Value
               
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
                                    "ObjectIdentifier" = "$thisComputerDomain-$memberSID"
                                    "ObjectType" = $memberType
                                }
                            } 
                        } 

                        # Non-default local groups
                        elseif ($memberSID -like "$thisComputerMachineSID*") {
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
                if ($result) {
                    $currentGroup["Results"] += $result
                }                                   
            }
            # Add each local group to script output
            $groups += $currentGroup
        }
    }

} catch {
    if ($logFilePath -ne "none") {
        "$((Get-Date).ToUniversalTime()) UTC - FETCH encountered an error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" | Out-File -FilePath $logFilePath -Append
    }
}

<#
-------------------------------------------
Format output and stage for SharpHound collection
-------------------------------------------
#>

$data = @(
    @{
        ObjectIdentifier = $thisComputerDomainSID
        Properties = @{
            name = $thisComputerFQDN
        }
        Sessions = $sessions | Sort-Object -Unique
        UserRights = $userRights
        LocalGroups = $groups
    }
)

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

# Use stdout if specified
if ($writeTo -eq "stdout") {
    #$output | ConvertTo-Json -Depth 6 -Compress
    $jsonOutput
} else {
# Use output directory for SMB collection if specified
    if ($outputToShare) {
        $todaysDirectory = Join-Path -Path $outputToShare -ChildPath (Get-Date -Format "yyyyMMdd")
        # Create a directory for today if it does not already exist
        if (-not (Test-Path $todaysDirectory)) {
            New-Item -Path $todaysDirectory -ItemType Directory
        }
        # Use the computer's domain SID in output files written to network shares
        $writeTo = Join-Path -Path $todaysDirectory -ChildPath "$($thisComputerDomainSID)_$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')).json"        
    }
    #$output | ConvertTo-Json -Depth 6 -Compress | Out-File $writeTo
    $jsonOutput | Out-File $writeTo
}

# End logging
if ($logFilePath -ne "none") {$ts = (Get-Date).ToUniversalTime(); "$ts UTC - FETCH execution completed" | Out-File -FilePath $logFilePath -Append}