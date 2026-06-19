<#
.SYNOPSIS
    Azure Multi-Tenant, ARG-First Azure Inventory Collector

.DESCRIPTION
    Collects comprehensive Azure resource inventory across one or more tenants using
    an ARG-first discovery model with ARM augmentation where required.

    Primary discovery is performed via Azure Resource Graph (ARG) for scale and speed,
    with targeted ARM calls used for:
      • VM power state and OS details
      • VM extension and agent health
      • Network Security Groups (rules + associations)
      • Load Balancers (frontend/backend configuration)

    Inventory is collected per tenant, across all enabled subscriptions, and exported
    as normalized CSV files into a single timestamped output folder.

    RESOURCE COVERAGE:
      • Virtual Machines
          - Power state, OS name/version
          - SKU (vCPU / Memory via cached SKU index)
          - Availability Zone / Set
          - NIC, subnet, private IP mapping
          - VM Agent, Azure Monitor Agent, MDE health
          - Managed & unmanaged disk sizing
          - Full raw tag capture with global normalization
      • Network Security Groups
          - Rules and effective NIC / subnet associations
      • Virtual Networks
          - Address spaces, subnets, NSG and route table references
      • Public IP Addresses
          - Allocation method, SKU, FQDN, NIC or NAT Gateway association
      • Load Balancers
          - Frontend IPs (public/private) and backend pools

    TAG HANDLING:
      • All tag keys are discovered tenant-wide across all runs
      • Raw tag keys are preserved exactly (case and spacing)
      • CSV output includes deterministic Tag_<RawKey> columns
      • Header collisions are safely resolved without data loss
      • No concat limits or truncation applied

    PERFORMANCE MODEL:
      • Sequential subscription processing (intentional)
      • Concurrent collectors per subscription (runspaces)
      • Concurrent per-VM extension health checks (runspaces)
      • Thread-safe Az module loading
      • Per-tenant SKU caching (region-aware, additive per run)

.OUTPUTS
    A single run output folder per execution containing:
      • VM_<timestamp>.csv
      • NSG_Custom_<timestamp>.csv
      • vNet_<timestamp>.csv
      • PIP_<timestamp>.csv
      • LBe_<timestamp>.csv

.PARAMETER None
    This script is fully interactive.

.INTERACTIVE PROMPTS
    • Tenant ID
    • Tenant type (Commercial or Azure Government)
    • Repeat execution for additional tenants (Y/N)

.NOTES
    AUTHOR:   Mark Lehrmann
    VERSION:  v7.5.1 (2026-03-19)

    RUNBOOK:
      v6.1 – last automation-tested version (pre multi-tenant refactor)

    DESIGN NOTES:
      • ARG is used wherever fidelity allows
      • ARM calls are intentionally limited to non-ARG-capable data
      • Subscription loops remain sequential for safety and auditability
      • KQL queries simplified to eliminate parser failures

.LIMITATIONS
    • No single-subscription or RG scoping (yet)
    • No Private Endpoint / Private DNS inventory
    • No Load Balancer backend VM resolution
    • Interactive-only (no parameterized automation mode)

.REQUIREMENTS
    • Az PowerShell modules:
        Az.Accounts
        Az.Resources
        Az.Compute
        Az.Network
    • Permissions to read resources across target subscriptions
    • Azure Resource Graph access enabled

.TODO
    [ ] Add subnet delegation
    [ ] Replace remaining ARM networking calls with ARG where possible
    [ ] JSON config file support (non-interactive mode)
    [ ] Subscription / Resource Group scoping parameters
    [ ] Inventory exclusions (by subscription or RG)
    [ ] Private Endpoint, Private DNS, and PLS inventory
    [ ] Production-grade logging + structured error output

.EXAMPLE
    .\az-arg.ps1
#>


#region Parameters
#################################
[CmdletBinding()]
param(
    [switch]$NoARM
)


#################################
#endregion Parameters

#region Generic helpers
#################################
function Add-RangeSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Target,

        [Parameter()]
        $Items
    )

    if ($null -eq $Target) { return }
    if ($null -eq $Items) { return }

    $arr = @($Items)
    if ($arr.Count -eq 0) { return }

    if ($Target -is [System.Collections.Generic.List[object]]) {
        $Target.AddRange($arr)
        return
    }

    $addRange = $Target.PSObject.Methods['AddRange']
    if ($addRange) {
        $null = $Target.AddRange($arr)
        return
    }

    $add = $Target.PSObject.Methods['Add']
    if ($add) {
        foreach ($x in $arr) { $null = $Target.Add($x) }
        return
    }

    if ($Target -is [object[]]) {
        Write-Verbose 'Add-RangeSafe: Target is array (fixed-size); skipping AddRange.'
        return
    }

    Write-Warning ("Add-RangeSafe: Target type '{0}' does not support Add/AddRange." -f $Target.GetType().FullName)
}

function Get-AllAzGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionId,

        [int]$MaxResults = 50000,
        [int]$BatchSize = 1000
    )

    $allResults = [System.Collections.Generic.List[object]]::new()

    $searchCmd = Get-Command Search-AzGraph -ErrorAction Stop
    $supportsSkipToken = $searchCmd.Parameters.ContainsKey('SkipToken')

    if ($supportsSkipToken) {
        $skipToken = $null

        do {
            $params = @{
                Query        = $Query
                First        = $BatchSize
                Subscription = $SubscriptionId
                ErrorAction  = 'Stop'
            }
            if ($skipToken) { $params.SkipToken = $skipToken }

            $resp = Search-AzGraph @params

            $pageData = if ($resp -and $resp.PSObject.Properties['Data']) { $resp.Data } else { $resp }
            $skipToken = if ($resp -and $resp.PSObject.Properties['SkipToken']) { $resp.SkipToken } else { $null }

            if (-not $pageData -or $pageData.Count -eq 0) { break }

            $allResults.AddRange(@($pageData))
        } while ($skipToken -and $allResults.Count -lt $MaxResults)
    }
    else {
        $skip = 0

        do {
            $params = @{
                Query        = $Query
                First        = $BatchSize
                Subscription = $SubscriptionId
                ErrorAction  = 'Stop'
            }
            if ($skip -gt 0) { $params.Skip = $skip }

            $resp = Search-AzGraph @params
            $pageData = if ($resp -and $resp.PSObject.Properties['Data']) { $resp.Data } else { $resp }

            if (-not $pageData -or $pageData.Count -eq 0) { break }

            $allResults.AddRange(@($pageData))
            $skip += $BatchSize
        } while ($pageData.Count -eq $BatchSize -and $allResults.Count -lt $MaxResults)
    }

    return $allResults
}

function Get-IdSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$SegmentName
    )

    $parts = $Id -split '/'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq $SegmentName -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }

    return $null
}
#################################
#endregion Generic helpers

#region Runspace helpers
#################################
function Initialize-AzRunspaceContext {
    [CmdletBinding()]
    param()

    Import-Module Az.Accounts -ErrorAction Stop

    $ctx = Get-AzContext -ErrorAction Stop
    $tenantId = $ctx.Tenant.Id

    try { Enable-AzContextAutosave -Scope Process | Out-Null } catch {
        try { Enable-AzContextAutosave -Scope CurrentUser | Out-Null } catch {
            try { Enable-AzContextAutosave | Out-Null } catch { }
        }
    }

    $path = Join-Path $env:TEMP ("azctx-{0}.json" -f ([guid]::NewGuid().ToString()))
    Save-AzContext -Path $path -Force | Out-Null

    [pscustomobject]@{
        TenantId      = [string]$tenantId
        AzContextPath = [string]$path
    }
}

function Invoke-RunspaceBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable[]]$Jobs,
        [Parameter(Mandatory)][int]$Throttle,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AzContextPath
    )

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
    $pool.ApartmentState = 'MTA'
    $pool.Open()

    $tasks = [System.Collections.Generic.List[object]]::new()

    $runner = {
        param(
            [string]$JobName,
            [string]$JobType,
            [string]$SubscriptionId,
            [string]$TenantId,
            [string]$AzContextPath,
            [hashtable]$JobArgs
        )

        # THREAD-SAFE MODULE IMPORT (serialize Import-Module across runspaces)
        $m = $null
        try {
            $m = [System.Threading.Mutex]::new($false, 'Global\AzModuleImportMutex')

            try { $null = $m.WaitOne(120000) } catch [System.Threading.AbandonedMutexException] { }

            Import-Module Az.Accounts  -Force -ErrorAction Stop | Out-Null
            Import-Module Az.Resources -Force -ErrorAction Stop | Out-Null
            Import-Module Az.Compute   -Force -ErrorAction Stop | Out-Null
            Import-Module Az.Network   -Force -ErrorAction Stop | Out-Null
        }
        catch {
            return [pscustomobject]@{
                Name  = $JobName
                Ok    = $false
                Error = "Module import failed in runspace: $($_.Exception.Message)"
                Data  = @()
            }
        }
        finally {
            if ($m) {
                try { $m.ReleaseMutex() } catch { }
                $m.Dispose()
            }
        }

        try {
            Import-AzContext -Path $AzContextPath -ErrorAction Stop | Out-Null
        }
        catch {
            return [pscustomobject]@{
                Name  = $JobName
                Ok    = $false
                Error = "Import-AzContext failed: $($_.Exception.Message)"
                Data  = @()
            }
        }

        try {
            # Establish subscription context inside runspace
            $subCtx = Get-AzContext -ListAvailable |
            Where-Object { $_.Subscription.Id -eq $SubscriptionId } |
            Select-Object -First 1

            if (-not $subCtx) {
                $subCtx = Set-AzContext -SubscriptionId $SubscriptionId -TenantId $TenantId -PassThru -ErrorAction Stop
            }
        }
        catch {
            return [pscustomobject]@{
                Name  = $JobName
                Ok    = $false
                Error = "Set-AzContext failed: $($_.Exception.Message)"
                Data  = @()
            }
        }

        try {
            switch ($JobType) {
                'NIC' { $data = @(Get-AzNetworkInterface     -DefaultProfile $subCtx -ErrorAction SilentlyContinue) }
                'NSG' { $data = @(Get-AzNetworkSecurityGroup -DefaultProfile $subCtx -ErrorAction SilentlyContinue) }
                'PIP' { $data = @(Get-AzPublicIpAddress      -DefaultProfile $subCtx -ErrorAction SilentlyContinue) }
                'LB' { $data = @(Get-AzLoadBalancer         -DefaultProfile $subCtx -ErrorAction SilentlyContinue) }
                'VMSTATUS' { $data = @(Get-AzVM -Status           -DefaultProfile $subCtx -ErrorAction Stop) }

                default { throw "Unknown JobType '$JobType'" }
            }

            [pscustomobject]@{
                Name  = $JobName
                Ok    = $true
                Error = $null
                Data  = $data
            }
        }
        catch {
            [pscustomobject]@{
                Name  = $JobName
                Ok    = $false
                Error = $_.Exception.Message
                Data  = @()
            }
        }
    }

    foreach ($job in $Jobs) {
        $name = [string]$job.Name
        $subId = [string]$job.SubscriptionId
        $type = [string]$job.JobType

        if ([string]::IsNullOrWhiteSpace($type)) {
            throw "Invoke-RunspaceBatch: Job '$name' is missing JobType."
        }

        $jobArgs = @{}
        if ($job.ContainsKey('Args') -and $null -ne $job.Args -and $job.Args -is [hashtable]) {
            $jobArgs = $job.Args
        }

        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool

        $null = $ps.AddScript($runner).
        AddArgument($name).
        AddArgument($type).
        AddArgument($subId).
        AddArgument($TenantId).
        AddArgument($AzContextPath).
        AddArgument($jobArgs)

        $handle = $ps.BeginInvoke()
        $tasks.Add([pscustomobject]@{ PS = $ps; Handle = $handle; Name = $name })
    }

    $results = @()
    foreach ($t in $tasks) {
        try {
            $results += $t.PS.EndInvoke($t.Handle)
        }
        catch {
            $results += [pscustomobject]@{
                Name  = $t.Name
                Ok    = $false
                Error = $_.Exception.Message
                Data  = @()
            }
        }
        finally {
            $t.PS.Dispose()
        }
    }

    $pool.Close()
    $pool.Dispose()

    return $results
}

function Get-VMExtensionHealthIndexRunspace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$VmRowsSub,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AzContextPath,
        [Parameter()][int]$Throttle = 12
    )

    if (-not $VmRowsSub -or $VmRowsSub.Count -eq 0) {
        return @{}
    }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
    $pool.ApartmentState = 'MTA'
    $pool.Open()

    $tasks = [System.Collections.Generic.List[object]]::new()

    $worker = {
        param(
            [string]$SubscriptionId,
            [string]$TenantId,
            [string]$AzContextPath,
            [string]$VmId,
            [string]$VmName,
            [string]$ResourceGroupName
        )

        Import-Module Az.Accounts, Az.Compute -ErrorAction SilentlyContinue | Out-Null

        try { Import-AzContext -Path $AzContextPath -ErrorAction Stop | Out-Null } catch {
            return [pscustomobject]@{
                Key               = $VmId
                VMName            = $VmName
                RG                = $ResourceGroupName
                VM_Agent_Status   = 'Unknown'
                AzureMonitorAgent = 'Not Installed'
                MDEAgent          = 'Not Installed'
            }
        }

        try {
            $subCtx = Get-AzContext -ListAvailable |
            Where-Object { $_.Subscription.Id -eq $SubscriptionId } |
            Select-Object -First 1

            if (-not $subCtx) {
                $subCtx = Set-AzContext -SubscriptionId $SubscriptionId -TenantId $TenantId -PassThru -ErrorAction Stop
            }
        }
        catch {
            return [pscustomobject]@{
                Key               = $VmId
                VMName            = $VmName
                RG                = $ResourceGroupName
                VM_Agent_Status   = 'Unknown'
                AzureMonitorAgent = 'Not Installed'
                MDEAgent          = 'Not Installed'
            }
        }

        function Resolve-ExtHealth {
            param($VmExtensions)

            $vmAgentStatus = 'Unknown'
            $amaStatus = 'Not Installed'
            $mdeStatus = 'Not Installed'

            if ($VmExtensions) {
                $extStatuses = $VmExtensions | ForEach-Object { $_.InstanceView.Statuses } | Where-Object { $_.Code }
                $isReady = ($extStatuses.Code -match 'succeeded') -or ($extStatuses.DisplayStatus -match 'Ready')
                $vmAgentStatus = if ($isReady) { 'Ready' } else { 'Issues' }

                foreach ($ext in $VmExtensions) {
                    $extName = [string]$ext.Name
                    $extType = [string]$ext.TypeHandlerVersion
                    $extPublisher = [string]$ext.Publisher
                    $probe = "$extName $extType $extPublisher"

                    $codes = @()
                    if ($ext.InstanceView -and $ext.InstanceView.Statuses) {
                        $codes = $ext.InstanceView.Statuses |
                        Where-Object { $_.Code } |
                        ForEach-Object { [string]$_.Code }
                    }
                    $isSucceeded = ($codes -match 'succeeded')

                    $isAmaMatch = ($probe -match 'AzureMonitor') -or
                    ($probe -match 'Microsoft\.Azure\.Monitor') -or
                    ($probe -match 'AzureMonitorWindowsAgent') -or
                    ($probe -match 'AzureMonitorLinuxAgent') -or
                    ($probe -match 'OmsAgentForLinux') -or
                    ($probe -match 'MicrosoftMonitoringAgent') -or
                    ($probe -match '\bMMA\b') -or
                    ($probe -match '\bOMS\b')

                    if ($amaStatus -eq 'Not Installed' -and $isAmaMatch) {
                        $amaStatus = if ($isSucceeded) { 'Healthy' } else { 'Installed, Not Healthy' }
                    }

                    $isMdeMatch = ($probe -match '\bMDE\b') -or
                    ($probe -match 'Defender') -or
                    ($probe -match 'DefenderForEndpoint') -or
                    ($probe -match 'MicrosoftDefender') -or
                    ($probe -match 'Mdatp') -or
                    ($probe -match 'Microsoft\.Azure\.Security') -or
                    ($probe -match 'Endpoint') -or
                    ($probe -match 'ATP') -or
                    ($probe -match 'MicrosoftDefenderForEndpoint') -or
                    ($probe -match 'AzureSecurity')

                    if ($mdeStatus -eq 'Not Installed' -and $isMdeMatch) {
                        $mdeStatus = if ($isSucceeded) { 'Healthy' } else { 'Installed, Not Healthy' }
                    }

                    if ($amaStatus -ne 'Not Installed' -and $mdeStatus -ne 'Not Installed') { break }
                }
            }

            [pscustomobject]@{
                VM_Agent_Status   = $vmAgentStatus
                AzureMonitorAgent = $amaStatus
                MDEAgent          = $mdeStatus
            }
        }

        $vmExtensions = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -Status -DefaultProfile $subCtx -ErrorAction SilentlyContinue
        $h = Resolve-ExtHealth -VmExtensions $vmExtensions

        [pscustomobject]@{
            Key               = $VmId
            VMName            = $VmName
            RG                = $ResourceGroupName
            VM_Agent_Status   = $h.VM_Agent_Status
            AzureMonitorAgent = $h.AzureMonitorAgent
            MDEAgent          = $h.MDEAgent
        }
    }

    foreach ($vmRow in $VmRowsSub) {
        $rg = [string]$vmRow.resourceGroup
        $name = [string]$vmRow.name
        $id = [string]$vmRow.id
        if (-not $rg -or -not $name -or -not $id) { continue }

        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool

        $null = $ps.AddScript($worker).
        AddArgument($SubscriptionId).
        AddArgument($TenantId).
        AddArgument($AzContextPath).
        AddArgument($id).
        AddArgument($name).
        AddArgument($rg)

        $handle = $ps.BeginInvoke()
        $tasks.Add([pscustomobject]@{ PS = $ps; Handle = $handle })
    }

    $index = @{}
    foreach ($t in $tasks) {
        try {
            $r = $t.PS.EndInvoke($t.Handle)
            foreach ($row in @($r)) {
                if ($row -and $row.Key) { $index[[string]$row.Key] = $row }
            }
        }
        catch {
        }
        finally {
            $t.PS.Dispose()
        }
    }

    $pool.Close()
    $pool.Dispose()

    return $index
}
#################################
#endregion Runspace helpers

#region Tenant Init and Start
#################################
$ErrorActionPreference = 'Continue'

$originalLocation = Get-Location
$runStampText = (Get-Date).ToString('yyyyMMdd_HHmm')
$CSV_VM_name = 'VM_'

# Initialize inventory mode based on the presence of the NoARM switch
$InventoryMode = if ($NoARM.IsPresent) {
    'NoARM / ARG-only inventory mode'
}
else {
    'Full inventory mode / ARG + targeted ARM augmentation'
}

Write-Host ("Inventory mode: {0}" -f $InventoryMode) -ForegroundColor Cyan


# Subscription concurrency (adjust based on scale and testing)
if (-not (Get-Variable -Name MaxConcurrency -Scope Script -ErrorAction SilentlyContinue)) {
    $script:MaxConcurrency = 12
}
$MaxConcurrency = $script:MaxConcurrency

# Multi-tenant inventory collections (Lists for performance)
$AzVM_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzNSG_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzvNet_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzPIP_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzLBe_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzOrphanDisk_Inventory_multi = [System.Collections.Generic.List[object]]::new()
$AzOrphanNIC_Inventory_multi = [System.Collections.Generic.List[object]]::new()

# Global tag collectors (accumulate across ALL tenants)
$globalTagKeysRaw = [System.Collections.Generic.HashSet[string]]::new()

# Initialize shared SKU cache (populate on demand based on discovered VM regions)
if (-not $script:SkuCache) {
    $script:SkuCache = @{
        Public = @{
            Regions = @{}
            Skus    = [System.Collections.Generic.List[object]]::new()
        }
        Gov    = @{
            Regions = @{}
            Skus    = [System.Collections.Generic.List[object]]::new()
        }
    }
}

# Main tenant repeat loop
$repeat = 'Y'

do {

    $Tenant = Read-Host 'Enter Tenant ID'

    # Tenant type affects Connect-AzAccount parameters and endpoints
    $yesOption = New-Object Management.Automation.Host.ChoiceDescription '&Yes', 'Commercial Tenant'
    $noOption = New-Object Management.Automation.Host.ChoiceDescription '&No', 'Government Tenant'
    $choices = @($yesOption, $noOption)

    $selectedIndex = $Host.UI.PromptForChoice('Tenant Type', 'Select Yes for commercial:', $choices, 0)
    $CommercialTenant = ($selectedIndex -eq 0)
    Write-Host ("Commercial Tenant: {0}" -f $CommercialTenant)

    try {
        if ($CommercialTenant) {
            $null = Connect-AzAccount -Tenant $Tenant -SkipContextPopulation -WarningAction SilentlyContinue -InformationAction SilentlyContinue -ErrorAction Stop
        }
        else {
            $null = Connect-AzAccount -Environment AzureUSGovernment -Tenant $Tenant -SkipContextPopulation -WarningAction SilentlyContinue -InformationAction SilentlyContinue -ErrorAction Stop
        }
    }
    catch {
        Write-Warning ("Azure sign-in failed for tenant {0}. Error: {1}" -f $Tenant, $_.Exception.Message)
        $repeat = 'Y'
        continue
    }

    # Initialize per-tenant inventory collections
    $AzVM_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzNSG_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzvNet_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzPIP_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzLBe_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzOrphanDisk_Inventory = [System.Collections.Generic.List[object]]::new()
    $AzOrphanNIC_Inventory = [System.Collections.Generic.List[object]]::new()


    $TenantDomain = (Get-AzTenant -TenantId $Tenant -ErrorAction Stop).DefaultDomain

    if (-not $script:RunOutputFolder) {
        $script:RunTenantDomain = $TenantDomain
        $script:RunOutputFolder = Join-Path 'C:\AzInventory' ("{0}_{1}" -f $TenantDomain, $runStampText)
        New-Item -Path $script:RunOutputFolder -ItemType Directory -Force | Out-Null
        Write-Host ("Run output folder created: {0}" -f $script:RunOutputFolder) -ForegroundColor Green
    }
    else {
        Write-Host ("Reusing run output folder: {0}" -f $script:RunOutputFolder) -ForegroundColor DarkGreen
    }

    Set-Location -Path $script:RunOutputFolder

    $rsCtx = Initialize-AzRunspaceContext
    $TenantId = $rsCtx.TenantId
    $AzContextPath = $rsCtx.AzContextPath

    # Subscriptions (optionally restrict by IDs)
    $targetSubIds = @()

    $subscription_list = Get-AzSubscription -TenantId $Tenant -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Id -and
        $_.State -eq 'Enabled' -and
        (-not $targetSubIds -or $targetSubIds.Count -eq 0 -or $_.Id -in $targetSubIds)
    }

    if (-not $subscription_list -or $subscription_list.Count -eq 0) {
        Write-Warning ("No subscriptions found for tenant {0}. Inventory will be empty." -f $Tenant)
    }

    # ARG: tenant-wide collection (bulk indexes for inventory processing)
    $subIds = @($subscription_list.Id) | Where-Object { $_ }

    $subscriptionNameById = @{}
    foreach ($sub in @($subscription_list)) {
        if ($sub.Id) { $subscriptionNameById[[string]$sub.Id] = [string]$sub.Name }
    }
    $vmsBySubscription = @{}
    $vmIndexById = @{}
    $vmNameById = @{}
    $nicIndexById = @{}
    $diskIndexById = @{}
    #################################
    #endregion Tenant Init and Start

    #region Queries
    #################################
    
    if ($subIds.Count -gt 0) {
        
        # ===== QUERY 1: Core VM Properties =====
        # Simplified KQL without 'let' statements for ARG parser compatibility
        $VM_CORE_QUERY = @'
Resources
| where type =~ "microsoft.compute/virtualmachines"
| extend
    vmIdLower = tolower(id),
    vmSize = tostring(properties.hardwareProfile.vmSize),
    timeCreated = todatetime(properties.timeCreated),
    availSetId = tostring(properties.availabilitySet.id),
    osType = tostring(properties.storageProfile.osDisk.osType),
    osDiskManagedId = tostring(properties.storageProfile.osDisk.managedDisk.id),
    osDiskName = tostring(properties.storageProfile.osDisk.name),
    imagePub = tostring(properties.storageProfile.imageReference.publisher),
    imageOffer = tostring(properties.storageProfile.imageReference.offer),
    imageSku = tostring(properties.storageProfile.imageReference.sku),
    licenseType = iif(isempty(tostring(properties.licenseType)), "NA", tostring(properties.licenseType)),
    argPowerState = tostring(properties.extended.instanceView.powerState.displayStatus),
    argOSName = tostring(properties.extended.instanceView.osName),
    argOSVersion = tostring(properties.extended.instanceView.osVersion)
| project
    id, subscriptionId, resourceGroup, name, location, zones, tags,
    vmIdLower, vmSize, timeCreated, availSetId, osType, osDiskManagedId,
    osDiskName, imagePub, imageOffer, imageSku, licenseType,
    argPowerState, argOSName, argOSVersion
'@

        # ===== QUERY 2: Disk Inventory =====
        $DISK_QUERY = @'
Resources
| where type =~ "microsoft.compute/disks"
| extend diskId = tolower(id)
| project
    diskId,
    diskSizeGB = toint(properties.diskSizeGB),
    diskSkuName = tostring(sku.name),
    diskState = tostring(properties.diskState)
'@

        # ===== QUERY 3: VM Extensions =====
        $EXTENSION_QUERY = @'
Resources
| where type =~ "microsoft.compute/virtualmachines/extensions"
| extend vmIdLower = tolower(tostring(split(id, "/extensions/")[0]))
| extend
    extensionProbe = strcat(
        tostring(name), " ",
        tostring(properties.publisher), " ",
        tostring(properties.type)
    )
| extend
    isAMA = extensionProbe has_cs "AzureMonitorWindowsAgent"
        or extensionProbe has_cs "AzureMonitorLinuxAgent"
        or extensionProbe has_cs "Microsoft.Azure.Monitor"
        or extensionProbe has_cs "AzureMonitor"
        or extensionProbe has_cs "OmsAgentForLinux"
        or extensionProbe has_cs "MicrosoftMonitoringAgent"
        or extensionProbe has_cs "MMA"
        or extensionProbe has_cs "OMS",
    isMDE = extensionProbe has_cs "MDE"
        or extensionProbe has_cs "Defender"
        or extensionProbe has_cs "DefenderForEndpoint"
        or extensionProbe has_cs "MicrosoftDefender"
        or extensionProbe has_cs "Mdatp"
        or extensionProbe has_cs "Microsoft.Azure.Security"
        or extensionProbe has_cs "Endpoint"
        or extensionProbe has_cs "ATP"
        or extensionProbe has_cs "AzureSecurity"
| project vmIdLower, extensionName = tostring(name), extensionPublisher = tostring(properties.publisher), isAMA, isMDE, provisioningState = tostring(properties.provisioningState)
'@

        # Execute Query 1: VM Core Data
        Write-Host "Executing VM core query..." -ForegroundColor Cyan
        try {
            $vmCoreResults = @(Get-AllAzGraph -Query $VM_CORE_QUERY -SubscriptionId $subIds -MaxResults 50000)
            Write-Host ("  ✓ Retrieved {0} VMs" -f $vmCoreResults.Count) -ForegroundColor Green
        }
        catch {
            Write-Error "VM core query failed: $_"
            $vmCoreResults = @()
        }

        # Execute Query 2: Disk Data
        Write-Host "Executing disk inventory query..." -ForegroundColor Cyan
        try {
            $diskResults = @(Get-AllAzGraph -Query $DISK_QUERY -SubscriptionId $subIds -MaxResults 50000)
            Write-Host ("  ✓ Retrieved {0} disks" -f $diskResults.Count) -ForegroundColor Green
        }
        catch {
            Write-Error "Disk query failed: $_"
            $diskResults = @()
        }

        # Execute Query 3: Extension Data
        Write-Host "Executing extension query..." -ForegroundColor Cyan
        try {
            $extensionResults = @(Get-AllAzGraph -Query $EXTENSION_QUERY -SubscriptionId $subIds -MaxResults 50000)
            Write-Host ("  ✓ Retrieved {0} extension records" -f $extensionResults.Count) -ForegroundColor Green
        }
        catch {
            Write-Error "Extension query failed: $_"
            $extensionResults = @()
        }

        # PowerShell-side join: Index disks by diskId
        $diskIndex = @{}
        foreach ($disk in $diskResults) {
            if ($disk.diskId) { $diskIndex[$disk.diskId] = $disk }
        }

        # PowerShell-side join: Group extensions by VM ID
        $extensionsByVmId = @{}
        foreach ($ext in $extensionResults) {
            if ($ext.vmIdLower) {
                if (-not $extensionsByVmId[$ext.vmIdLower]) {
                    $extensionsByVmId[$ext.vmIdLower] = @()
                }
                $extensionsByVmId[$ext.vmIdLower] += $ext
            }
        }

        # Merge results for each VM
        foreach ($vm in $vmCoreResults) {
            # Add disk info if OS disk is managed
            if ($vm.osDiskManagedId -and $diskIndex[$vm.osDiskManagedId]) {
                $osDiskInfo = $diskIndex[$vm.osDiskManagedId]
                $vm | Add-Member -NotePropertyName osDiskSizeGB -NotePropertyValue $osDiskInfo.diskSizeGB -Force
                $vm | Add-Member -NotePropertyName osDiskSkuName -NotePropertyValue $osDiskInfo.diskSkuName -Force
                $vm | Add-Member -NotePropertyName osDiskState -NotePropertyValue $osDiskInfo.diskState -Force
            }

            # Add extension health counts
            if ($extensionsByVmId[$vm.vmIdLower]) {
                $vmExts = $extensionsByVmId[$vm.vmIdLower]
                $amaCount = @($vmExts | Where-Object { $_.isAMA }).Count
                $mdeCount = @($vmExts | Where-Object { $_.isMDE }).Count
                $amaSucceeded = @($vmExts | Where-Object { $_.isAMA -and $_.provisioningState -match 'Succeeded' }).Count
                $mdeSucceeded = @($vmExts | Where-Object { $_.isMDE -and $_.provisioningState -match 'Succeeded' }).Count

                $vm | Add-Member -NotePropertyName AMA_Count_ARG -NotePropertyValue $amaCount -Force
                $vm | Add-Member -NotePropertyName MDE_Count_ARG -NotePropertyValue $mdeCount -Force
                $vm | Add-Member -NotePropertyName AMA_Succeeded_Count_ARG -NotePropertyValue $amaSucceeded -Force
                $vm | Add-Member -NotePropertyName MDE_Succeeded_Count_ARG -NotePropertyValue $mdeSucceeded -Force
            }

            # Add to per-tenant inventory
            $AzVM_Inventory.Add($vm)
        }

        Write-Host ("Total VMs processed for tenant: {0}" -f $AzVM_Inventory.Count) -ForegroundColor Cyan
    }
    
    #################################
    #endregion Queries

    Write-Host "Processing complete for tenant $Tenant" -ForegroundColor Green
    
    # Prompt for additional tenants
    $response = Read-Host "Collect inventory for another tenant? (Y/N)"
    $repeat = if ($response -match '^[yY]') { 'Y' } else { 'N' }

} while ($repeat -match '^[yY]')

Write-Host "Inventory collection complete. Output saved to: $($script:RunOutputFolder)" -ForegroundColor Green
