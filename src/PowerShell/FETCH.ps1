<#
-------------------------------------------
FETCH: Fleetwide Enumeration Tool for Configuration Hierarchies

Author: SpecterOps
Purpose:
  - Collect local sessions, user rights assignments, and group members
  - Stage output for SharpHound collection via centralized management tools

-------------------------------------------
#>

# Command line option to write output to JSON file or stdout
param(
    [ValidateScript({
        if ($_ -eq "stdout" -or $_ -match '\.json$') {
            $true
        } else {
            throw "Output must be 'stdout' or a file path ending in '.json'"
        }
    })]
    [string]$OutputParam = "C:\Windows\CCM\ScriptStore\FetchResults.json"
)


# Collect local system domain computer account SID via LDAP
$ComputerName = $env:COMPUTERNAME
$ADAccount = New-Object System.Security.Principal.NTAccount($ComputerName + "$")
$ComputerDomainSID = $ADAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

# Collect local system FQDN
$ComputerFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName


<#
-------------------------------------------
Collect sessions
-------------------------------------------
#>

# Define timespan for session collection
$sevenDaysAgo = (Get-Date).AddDays(-7)

# Define Event IDs to collect
$EventIDs = 4624#, 4648
$eventResults = @()

foreach ($EventID in $EventIDs) {
    $events = Get-WinEvent -FilterHashtable @{Logname='Security';ID=$EventID;StartTime=$sevenDaysAgo}
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
                
                # Resolve the source IP address to a hostname
                $ComputerName = Resolve-DnsName -Name $ipAddress -Type PTR
                $ADAccount = New-Object System.Security.Principal.NTAccount($ComputerName.NameHost.Split(".")[0] + "$")
                $SourceComputerDomainSID = $ADAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }

            else {
                # Collect local logon sessions on this host
                $SourceComputerDomainSID = $ComputerDomainSID
            }
            
            # Add results to output
            $eventResults += @{
                UserSID = $userSID
                ComputerSID = $SourceComputerDomainSID
            }
        }
    }
}

$sessions = @{
    "Results" = $eventResults | Sort-Object -Unique
    "Collected" = $true
    "FailureReason" = $null
}


<#
-------------------------------------------
Collect local user rights assignments
-------------------------------------------
#>

# Export the security configuration to a file
secedit /export /areas USER_RIGHTS /cfg "secedit.cfg"

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
            Sessions = $sessions
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