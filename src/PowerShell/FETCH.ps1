﻿<#
-------------------------------------------
FETCH: Flexible Enumeration Tool for Centrally-managed Hosts

Author: SpecterOps
Purpose:
  - Collect local sessions, user rights assignments, and group members
  - Stage output for SharpHound collection via centralized management tools

-------------------------------------------
#>

param(
    # Validate that the log file path exists or is set to "none" (default: "C:\Windows\CCM\ScriptStore\FetchExecution.log")
    [ValidateScript({
        if ($_ -eq "none" -or (Test-Path (Split-Path -Path $_))) {
            $true
        } elseif (-not (Test-Path (Split-Path -Path $_))) {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        } else {
            throw "Output must be 'none' or a valid local/remote file path"
        }
    })]
    [string]$logParam = "C:\Windows\CCM\ScriptStore\FetchExecution.log",

    # Validate that the output file path exists or is set to "stdout" (default: "C:\Windows\CCM\ScriptStore\FetchResults.json")
    [ValidateScript({
        if ($_ -eq "stdout" -or ((Test-Path (Split-Path -Path $_)) -and $_ -match '\.json$')) {
            $true
        } elseif (-not (Test-Path (Split-Path -Path $_))) {
            throw "The specified directory does not exist: $(Split-Path -Path $_)"
        } else {
            throw "Output must be 'stdout' or a local/remote file path ending in '.json'"
        }
    })]
    [string]$outputParam = "C:\Windows\CCM\ScriptStore\FetchResults.json",

    # Number of days behind to fetch sessions (default: 7)
    [ValidateRange(1,365)]
    [int]$sessionLookbackDays = 7
)

# Initialize logging
if ($logParam -ne "none") {
    $nowTimeStamp = (Get-Date).ToUniversalTime()
    "$nowTimeStamp UTC - FETCH execution started" | Out-File -FilePath $logParam -Append
    }

# Catch and log execution error messages
try {
    <#
    -------------------------------------------
    Collect sessions
    -------------------------------------------
    #>

    # Collect local system domain computer account SID via LDAP
    $thisComputerName = $env:COMPUTERNAME
    $thisComputerDomainAccount = New-Object System.Security.Principal.NTAccount("${thisComputerName}$")
    $thisComputerDomainSID = $thisComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

    # Collect local system FQDN
    $thisComputerFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName

    # Define timespan for session collection
    $sessionLookbackStartDate = (Get-Date).AddDays(-$sessionLookbackDays)

    # Define Event IDs to collect
    $eventIDs = 4624, 4648
    $logonEventResults = @()

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
                
                    # Collect domain user logon sessions
                    if ($targetUserSID -like "S-1-5-21-*") {
         
                        # Collect sessions initiated from remote hosts (Logon Type 3: Network)
                        if ($sourceIPAddress) {
       
                            # Resolve the source IP address to a hostname, discarding non-terminating errors (failed resolution)
                            $sourceComputerName = Resolve-DnsName -Name $sourceIPAddress -Type PTR 2>$null

                            # Translate the hostname to a domain SID
                            if ($sourceComputerName) {
                                $sourceComputerDomainAccount = New-Object System.Security.Principal.NTAccount($sourceComputerName.NameHost.Split(".")[0] + "$")
                            }

                            if ($sourceComputerDomainAccount) {
                                $sourceComputerDomainSID = $sourceComputerDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            }
                        }
                        # Collect local logon sessions on this host
                        else {
                            $sourceComputerDomainSID = $thisComputerDomainSID
                        }

                        # Create a record for this domain user session
                        $newSession = @{
                            UserSID = $targetUserSID
                            ComputerSID = $sourceComputerDomainSID
                            LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                        }

                        # Check if a session with the same UserSID and ComputerSID already exists
                        $existingSession = $logonEventResults | Where-Object { $_.UserSID -eq $targetUserSID -and $_.ComputerSID -eq $sourceComputerDomainSID }

                        if ($existingSession) {
                            # If a session with the same UserSID and ComputerSID is found, compare LastSeen times and update if the new one is more recent
                            if ($newSession.LastSeen -gt $existingSession.LastSeen) {
                                $existingSession.LastSeen = $newSession.LastSeen
                            }
                        } else {
                            # If no session with the same UserSID and ComputerSID is found, add the session to the script output
                            $logonEventResults += $newSession
                        }
                    }
                }

                4648 {
                    # Initialize fields to use to filter log data
                    $targetUserName = $eventData | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
                    $targetDomainName = $eventData | Where-Object { $_.Name -eq 'TargetDomainName' } | Select-Object -ExpandProperty '#text'

                    # Convert TargetUserName and TargetDomainName to domain SID
                    $targetUserDomainAccount = New-Object System.Security.Principal.NTAccount("$targetDomainName\$targetUserName")
                    $targetUserDomainSID = $targetUserDomainAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                    # Collect domain user logon sessions on this host that did not originate from SYSTEM
                    if ($targetUserDomainSID -like "S-1-5-21-*" -and $targetUserDomainSID -ne $thisComputerDomainSID) {
                        # Create a record for this domain user session
                        $newSession = @{
                            UserSID = $targetUserDomainSID
                            ComputerSID = $thisComputerDomainSID
                            LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                        }

                        # Check if a session with the same UserSID and ComputerSID already exists
                        $existingSession = $logonEventResults | Where-Object { $_.UserSID -eq $targetUserDomainSID -and $_.ComputerSID -eq $thisComputerDomainSID }

                        if ($existingSession) {
                            # If a session with the same UserSID and ComputerSID is found, compare LastSeen times and update if the new one is more recent
                            if ($newSession.LastSeen -gt $existingSession.LastSeen) {
                                $existingSession.LastSeen = $newSession.LastSeen
                            }
                        } else {
                            # If no session with the same UserSID and ComputerSID is found, add the session to the script output
                            $logonEventResults += $newSession
                        }
                    }
                }
            }
        }
    }
    
    $sessions = @{
        "Results" = $logonEventResults 
        "Collected" = $true
        "FailureReason" = $null
    }


    <#
    -------------------------------------------
    Collect local user rights assignments
    -------------------------------------------
    #>

    # Export the security configuration to a file, discarding non-terminating errors to prevent stdout pollution
    secedit /export /areas USER_RIGHTS /cfg "secedit.cfg" > $null 2>&1

    # Read the contents of the exported file
    $seceditContents = Get-Content "secedit.cfg" -Raw

    # Remove the exported file
    Remove-Item "secedit.cfg"

    # Extract and format user rights assignments from the secedit output
    # $userRightsLines = $seceditContents -split "`r`n" | Where-Object { $_ -like "Se*" }
    # Only collect for CanRDP edge pending BloodHound support for additional URAs
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

    foreach ($group in $(Get-LocalGroup)) {
        # Exclude domain groups on domain controllers
        if ($group.PrincipalSource -eq "Local" -and $group.SID.Value -notcontains $ComputerDomainSID) {
            # Store attributes for each local group
            $currentGroup = @{
            # Replace built-in local group SIDs with domain computer SID
            "ObjectIdentifier" = $($group.SID.Value.Replace("S-1-5-32", $ComputerDomainSID))
            "Name" = $group.Name.ToUpper() + "@" + $ComputerFQDN
            "Results" = @()
            "LocalNames" = @()
            "Collected" = $true
            "FailureReason" = $null
            }

            # Add local group members that are AD principals to output for the current local group
            $members = Get-LocalGroupMember -Group $group.Name
            foreach ($member in $($members | Where-Object { $_.PrincipalSource -eq "ActiveDirectory" })) {
                $memberId = @{
                    "ObjectIdentifier" = $member.SID.Value
                }
                $currentGroup["Results"] += $memberId   
            }

            # Add each local group to script output
            $groups += $currentGroup
        }
    }

} catch {
    if ($logParam -ne "none") {
        "$((Get-Date).ToUniversalTime()) UTC - FETCH encountered an error at line $_.InvocationInfo.ScriptLineNumber: $($_.Exception.Message)" | Out-File -FilePath $logParam -Append
    }
}

<#
-------------------------------------------
Format output and stage for SharpHound collection
-------------------------------------------
#>

$output = @{
    data = @(
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
    meta = @{
        methods = 107028
        type = "computers"
        count = ($output.data).Count
        # Version is also replaced by SharpHound before upload to ingest API
        version = 5
    }
}

if ($outputParam -eq "stdout") {
    $output | ConvertTo-Json -Depth 6 -Compress
} else {
    $output | ConvertTo-Json -Depth 6 -Compress | Out-File $outputParam
}

# End logging
if ($logParam -ne "none") {$ts = (Get-Date).ToUniversalTime(); "$ts UTC - FETCH execution completed" | Out-File -FilePath $logParam -Append}