<#
-------------------------------------------
FETCH: Flexible Enumeration Tool for Centrally-managed Hosts

Author: SpecterOps
Purpose:
  - Collect local sessions, user rights assignments, and group members
  - Stage output for SharpHound collection via centralized management tools

-------------------------------------------
#>


<#
-------------------------------------------
Command line options for output and logging
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
    [string]$LogParam = "C:\Windows\CCM\ScriptStore\FetchExecution.log",

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
    [string]$OutputParam = "C:\Windows\CCM\ScriptStore\FetchResults.json",

    # Number of days behind to fetch sessions (default: 7)
    [ValidateRange(1,365)]
    [int]$SessionLookbackDays = 7
)

# Initialize logging
if ($LogParam -ne "none") {$ts = (Get-Date).ToUniversalTime(); "$ts UTC - FETCH execution started" | Out-File -FilePath $LogParam -Append}

# Catch and log execution error messages
try {
    <#
    -------------------------------------------
    Collect sessions
    -------------------------------------------
    #>

    # Collect local system domain computer account SID via LDAP
    $ComputerName = $env:COMPUTERNAME
    $ADAccount = New-Object System.Security.Principal.NTAccount($ComputerName + "$")
    $ComputerDomainSID = $ADAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

    # Collect local system FQDN
    $ComputerFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName

    # Define timespan for session collection
    $SessionLookbackStartDate = (Get-Date).AddDays(-$SessionLookbackDays)

    # Define Event IDs to collect
    $EventIDs = 4624#, 4648
    $eventResults = @()

    foreach ($EventID in $EventIDs) {
        $events = Get-WinEvent -FilterHashtable @{Logname='Security';ID=$EventID;StartTime=$SessionLookbackStartDate}
        foreach ($event in $events) {
            
            $eventXml = [xml]$event.ToXml()
            $eventData = $eventXml.Event.EventData.Data

            # Initialize fields to use to filter log data
            $userSID = $eventData | Where-Object { $_.Name -eq 'TargetUserSid' } | Select-Object -ExpandProperty '#text'
            $logonType = $eventData | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
            $ipAddress = $eventData | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
        
            # Collect user logon sessions on this host 
            if ($userSID -like "S-1-5-21-*") {
         
                # Collect sessions initiated from remote hosts (Logon Type 3: Network)
                if ($ipAddress) {
       
                    # Resolve the source IP address to a hostname, discarding non-terminating errors (failed resolution)
                    $ComputerName = Resolve-DnsName -Name $ipAddress -Type PTR 2>$null

                    if ($ComputerName) {
                        $ADAccount = New-Object System.Security.Principal.NTAccount($ComputerName.NameHost.Split(".")[0] + "$")
                    }

                    if ($ADAccount) {
                        $SourceComputerDomainSID = $ADAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                }
                else {
                    # Collect local logon sessions on this host
                    $SourceComputerDomainSID = $ComputerDomainSID
                }

                # Create a record for this domain user session
                $newSession = @{
                    UserSID = $userSID
                    ComputerSID = $SourceComputerDomainSID
                    LastSeen = "{0:yyyy-MM-dd HH:mm} UTC" -f $event.TimeCreated.ToUniversalTime()
                }

                # Check if a session with the same UserSID and ComputerSID already exists
                $existingSession = $eventResults | Where-Object { $_.UserSID -eq $userSID -and $_.ComputerSID -eq $SourceComputerDomainSID }

                if ($existingSession) {
                    # If a session with the same UserSID and ComputerSID is found, compare LastSeen times and update if the new one is more recent
                    if ($newSession.LastSeen -gt $existingSession.LastSeen) {
                        $existingSession.LastSeen = $newSession.LastSeen
                    }
                } else {
                    # If no session with the same UserSID and ComputerSID is found, add the session to the script output
                    $eventResults += $newSession
                }
            }
        }
    }

    $sessions = @{
        "Results" = $eventResults 
        "Collected" = $true
        "FailureReason" = $null
    }


    <#
    -------------------------------------------
    Collect local user rights assignments
    -------------------------------------------
    #>

    # Export the security configuration to a file, discarding non-terminating errors to prevent stdout pollution
    secedit /export /areas USER_RIGHTS /cfg "secedit.cfg" > NUL 2>&1

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
        $lineParts = $line -split "=" # Split SIDs from rights assignments
        $right = $lineParts[0].Trim() 
        $sids = $lineParts[1].Trim() -split "," # Split SIDs into a list
        $sids = $sids | ForEach-Object {
            $sid = $_ -replace "^\*", "" # Remove leading asterisk from each SID
            $sid = $sid -replace "S-1-5-32", $ComputerDomainSID  # Replace built-in local group SIDs with domain computer SID
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
    if ($LogParam -ne "none") {$ts = (Get-Date).ToUniversalTime(); "$ts UTC - FETCH encountered a terminating error: $($_.Exception.Message)" | Out-File -FilePath $LogParam -Append}
}

<#
-------------------------------------------
Format output and stage for SharpHound collection
-------------------------------------------
#>

$output = @{
    data = @(
        @{
            ObjectIdentifier = $ComputerDomainSID
            Properties = @{
                name = $ComputerFQDN
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

if ($OutputParam -eq "stdout") {
    $output | ConvertTo-Json -Depth 6 -Compress
} else {
    $output | ConvertTo-Json -Depth 6 -Compress | Out-File $OutputParam
}

# End logging
if ($LogParam -ne "none") {$ts = (Get-Date).ToUniversalTime(); "$ts UTC - FETCH execution completed" | Out-File -FilePath $LogParam -Append}