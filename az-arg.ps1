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
    VERSION:  v7.5.0 (2026-03-13)

    RUNBOOK:
      v6.1 – last automation-tested version (pre multi-tenant refactor)

    DESIGN NOTES:
      • ARG is used wherever fidelity allows
      • ARM calls are intentionally limited to non-ARG-capable data
      • Subscription loops remain sequential for safety and auditability

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
    .\Ex-Az_Inventory_multitenant.ps1
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
        $VM_BASE_QUERY = @'
let diskInventory =
    Resources
    | where type =~ "microsoft.compute/disks"
    | extend
        diskId              = tolower(id),
        diskSizeGB          = toint(properties.diskSizeGB),
        diskAccessId        = tostring(properties.diskAccessId),
        diskTimeCreated     = todatetime(properties.timeCreated),
        diskState           = tostring(properties.diskState),
        diskSkuName         = tostring(sku.name),
        diskOsType          = tostring(properties.osType)
    | project
        diskId,
        diskSizeGB,
        diskAccessId,
        diskTimeCreated,
        diskState,
        diskSkuName,
        diskOsType;

let vmCore =
    Resources
    | where type =~ "microsoft.compute/virtualmachines"
    | extend
        props                   = properties,
        vmIdLower               = tolower(id),
        vmSize                  = tostring(properties.hardwareProfile.vmSize),
        timeCreated             = todatetime(properties.timeCreated),
        availSetId              = tostring(properties.availabilitySet.id),
        osType                  = tostring(properties.storageProfile.osDisk.osType),
        osDiskManagedIdRaw      = tostring(properties.storageProfile.osDisk.managedDisk.id),
        osDiskManagedIdLower    = tolower(tostring(properties.storageProfile.osDisk.managedDisk.id)),
        osDiskName              = tostring(properties.storageProfile.osDisk.name),
        osDiskVhdUri            = tostring(properties.storageProfile.osDisk.vhd.uri),
        dataDisks               = properties.storageProfile.dataDisks,
        imagePub                = tostring(properties.storageProfile.imageReference.publisher),
        imageOffer              = tostring(properties.storageProfile.imageReference.offer),
        imageSku                = tostring(properties.storageProfile.imageReference.sku),
        imageVersion            = tostring(properties.storageProfile.imageReference.version),
        adminUser               = tostring(properties.osProfile.adminUsername),
        computerName            = tostring(properties.osProfile.computerName),
        nicRefs                 = properties.networkProfile.networkInterfaces,
        licenseType             = iif(isempty(tostring(properties.licenseType)), "NA", tostring(properties.licenseType)),
        argPowerState           = tostring(properties.extended.instanceView.powerState.displayStatus),
        argPowerStateCode       = tostring(properties.extended.instanceView.powerState.code),
        argOSName               = tostring(properties.extended.instanceView.osName),
        argOSVersion            = tostring(properties.extended.instanceView.osVersion),
        argHyperVGeneration     = tostring(properties.extended.instanceView.hyperVGeneration)
    | lookup kind=leftouter diskInventory on $left.osDiskManagedIdLower == $right.diskId
    | project
        id,
        vmIdLower,
        subscriptionId,
        resourceGroup,
        name,
        location,
        zones,
        tags,
        licenseType,
        vmSize,
        timeCreated,
        availSetId,
        osType,
        osDiskManagedId = osDiskManagedIdRaw,
        osDiskName,
        osDiskVhdUri,
        dataDisks,
        imagePub,
        imageOffer,
        imageSku,
        imageVersion,
        adminUser,
        computerName,
        nicRefs,
        argPowerState,
        argPowerStateCode,
        argOSName,
        argOSVersion,
        argHyperVGeneration,
        osDiskSizeGB = diskSizeGB,
        osDiskAccessId = diskAccessId,
        osDiskTimeCreated = diskTimeCreated,
        osDiskState = diskState,
        osDiskSkuName = diskSkuName;

let vmDataDiskRefs =
    Resources
    | where type =~ "microsoft.compute/virtualmachines"
    | extend vmIdLower = tolower(id)
    | extend dataDisks = properties.storageProfile.dataDisks
    | mv-expand dataDisk = dataDisks to typeof(dynamic)
    | extend
        dataDiskName       = tostring(dataDisk.name),
        dataDiskManagedId  = tostring(dataDisk.managedDisk.id),
        dataDiskIdLower    = tolower(tostring(dataDisk.managedDisk.id)),
        dataDiskLun        = tostring(dataDisk.lun),
        dataDiskCaching    = tostring(dataDisk.caching),
        dataDiskCreateOpt  = tostring(dataDisk.createOption)
    | lookup kind=leftouter diskInventory on $left.dataDiskIdLower == $right.diskId
    | summarize
        DataDiskNames_ARG          = make_set(dataDiskName, 1000),
        DataDiskIds_ARG            = make_set(dataDiskManagedId, 1000),
        DataDiskLuns_ARG           = make_set(dataDiskLun, 1000),
        DataDiskCaching_ARG        = make_set(dataDiskCaching, 1000),
        DataDiskCreateOptions_ARG  = make_set(dataDiskCreateOpt, 1000),
        DataDiskSkuNames_ARG       = make_set(diskSkuName, 1000),
        DataDiskSizeGB_ARG         = sum(tolong(coalesce(diskSizeGB, 0)))
      by vmIdLower;

let nicIpInventory =
    Resources
    | where type =~ "microsoft.network/networkinterfaces"
    | extend
        nicIdLower          = tolower(id),
        nicName             = tostring(name),
        nicLocation         = tostring(location),
        nicResourceGroup    = tostring(resourceGroup),
        nicVmIdLower        = tolower(tostring(properties.virtualMachine.id)),
        nicNsgId            = tostring(properties.networkSecurityGroup.id),
        privateEndpointId   = tostring(properties.privateEndpoint.id),
        managedById         = tostring(managedBy),
        ipConfigs           = properties.ipConfigurations
    | mv-expand ipConfig = ipConfigs to typeof(dynamic)
    | extend
        ipConfigName        = tostring(ipConfig.name),
        privateIp           = tostring(ipConfig.properties.privateIPAddress),
        privateIpAlloc      = tostring(ipConfig.properties.privateIPAllocationMethod),
        privateIpVersion    = tostring(ipConfig.properties.privateIPAddressVersion),
        subnetId            = tostring(ipConfig.properties.subnet.id),
        publicIpId          = tostring(ipConfig.properties.publicIPAddress.id),
        primaryIpConfig     = tostring(ipConfig.properties.primary),
        vNetName            = extract(@"/virtualNetworks/([^/]+)/", 1, tostring(ipConfig.properties.subnet.id)),
        subnetName          = extract(@"/subnets/([^/]+)$", 1, tostring(ipConfig.properties.subnet.id))
    | where isnotempty(nicVmIdLower)
    | summarize
        ifName_ARG             = make_set(nicName, 1000),
        ifId_ARG               = make_set(nicIdLower, 1000),
        vNet_ARG               = make_set(vNetName, 1000),
        Subnet_ARG             = make_set(subnetName, 1000),
        SubnetId_ARG           = make_set(subnetId, 1000),
        PrivateIP_ARG          = make_set(privateIp, 1000),
        PrivateIPalloc_ARG     = make_set(privateIpAlloc, 1000),
        PrivateIPVersion_ARG   = make_set(privateIpVersion, 1000),
        PublicIPId_ARG         = make_set(publicIpId, 1000),
        NIC_NSG_Id_ARG         = make_set(nicNsgId, 1000),
        IPConfigName_ARG       = make_set(ipConfigName, 1000),
        PrimaryIPConfig_ARG    = make_set(primaryIpConfig, 1000)
      by vmIdLower = nicVmIdLower;

let vmExtensions =
    Resources
    | where type =~ "microsoft.compute/virtualmachines/extensions"
    | extend
        vmIdLower              = tolower(tostring(split(id, "/extensions/")[0])),
        extensionName          = tostring(name),
        extensionPublisher     = tostring(properties.publisher),
        extensionType          = tostring(properties.type),
        extensionTypeVersion   = tostring(properties.typeHandlerVersion),
        extensionAutoUpgrade   = tostring(properties.autoUpgradeMinorVersion),
        extensionProvisioning  = tostring(properties.provisioningState),
        extensionProbe         = strcat(
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
                or extensionProbe has_cs "MicrosoftDefenderForEndpoint"
                or extensionProbe has_cs "AzureSecurity"
    | summarize
        ExtensionNames_ARG              = make_set(extensionName, 1000),
        ExtensionPublishers_ARG         = make_set(extensionPublisher, 1000),
        ExtensionTypes_ARG              = make_set(extensionType, 1000),
        ExtensionTypeVersions_ARG       = make_set(extensionTypeVersion, 1000),
        ExtensionProvisioningStates_ARG = make_set(extensionProvisioning, 1000),
        AMA_ExtensionNames_ARG          = make_set_if(extensionName, isAMA, 1000),
        AMA_ProvisioningStates_ARG      = make_set_if(extensionProvisioning, isAMA, 1000),
        MDE_ExtensionNames_ARG          = make_set_if(extensionName, isMDE, 1000),
        MDE_ProvisioningStates_ARG      = make_set_if(extensionProvisioning, isMDE, 1000),
        AMA_Count_ARG                   = countif(isAMA),
        AMA_Succeeded_Count_ARG         = countif(isAMA and extensionProvisioning =~ "Succeeded"),
        MDE_Count_ARG                   = countif(isMDE),
        MDE_Succeeded_Count_ARG         = countif(isMDE and extensionProvisioning =~ "Succeeded")
      by vmIdLower;

vmCore
| lookup kind=leftouter nicIpInventory on vmIdLower
| lookup kind=leftouter vmDataDiskRefs on vmIdLower
| lookup kind=leftouter vmExtensions on vmIdLower
| extend
    VMStatus_ARG = case(
        isnotempty(argPowerState), argPowerState,
        isnotempty(argPowerStateCode), argPowerStateCode,
        "ARG:NotReported"
    ),
    VM_Agent_Status_ARG = case(
        isnotempty(argOSName) or isnotempty(argOSVersion) or isnotempty(argPowerState), "ARG:InstanceViewPresent",
        "ARG:NotAvailable"
    ),
    AzureMonitorAgent_ARG = case(
        coalesce(AMA_Count_ARG, 0) == 0, "Not Installed",
        coalesce(AMA_Succeeded_Count_ARG, 0) > 0, "Installed",
        "Installed, Provisioning Not Succeeded"
    ),
    MDEAgent_ARG = case(
        coalesce(MDE_Count_ARG, 0) == 0, "Not Installed",
        coalesce(MDE_Succeeded_Count_ARG, 0) > 0, "Installed",
        "Installed, Provisioning Not Succeeded"
    ),
    TotalManagedDiskSizeGB_ARG = tolong(coalesce(osDiskSizeGB, 0)) + tolong(coalesce(DataDiskSizeGB_ARG, 0)),
    DataDiskNames_Text_ARG = strcat_array(DataDiskNames_ARG, ";"),
    ifName_Text_ARG = strcat_array(ifName_ARG, ";"),
    vNet_Text_ARG = strcat_array(vNet_ARG, ";"),
    Subnet_Text_ARG = strcat_array(Subnet_ARG, ";"),
    PrivateIP_Text_ARG = strcat_array(PrivateIP_ARG, ";"),
    PrivateIPalloc_Text_ARG = strcat_array(PrivateIPalloc_ARG, ";"),
    ExtensionNames_Text_ARG = strcat_array(ExtensionNames_ARG, ";"),
    ExtensionTypes_Text_ARG = strcat_array(ExtensionTypes_ARG, ";")
| project
    id,
    subscriptionId,
    resourceGroup,
    name,
    location,
    zones,
    tags,
    licenseType,
    vmSize,
    timeCreated,
    availSetId,
    osType,
    osDiskManagedId,
    osDiskName,
    osDiskVhdUri,
    dataDisks,
    imagePub,
    imageOffer,
    imageSku,
    imageVersion,
    adminUser,
    computerName,
    nicRefs,
    VMStatus_ARG,
    VM_Agent_Status_ARG,
    AzureMonitorAgent_ARG,
    MDEAgent_ARG,
    osDiskSizeGB,
    osDiskAccessId,
    osDiskTimeCreated,
    osDiskState,
    osDiskSkuName,
    DataDiskNames_ARG,
    DataDiskIds_ARG,
    DataDiskLuns_ARG,
    DataDiskCaching_ARG,
    DataDiskCreateOptions_ARG,
    DataDiskSkuNames_ARG,
    DataDiskSizeGB_ARG,
    TotalManagedDiskSizeGB_ARG,
    DataDiskNames_Text_ARG,
    ifName_ARG,
    ifId_ARG,
    vNet_ARG,
    Subnet_ARG,
    SubnetId_ARG,
    PrivateIP_ARG,
    PrivateIPalloc_ARG,
    PrivateIPVersion_ARG,
    PublicIPId_ARG,
    NIC_NSG_Id_ARG,
    IPConfigName_ARG,
    PrimaryIPConfig_ARG,
    ifName_Text_ARG,
    vNet_Text_ARG,
    Subnet_Text_ARG,
    PrivateIP_Text_ARG,
    PrivateIPalloc_Text_ARG,
    ExtensionNames_ARG,
    ExtensionPublishers_ARG,
    ExtensionTypes_ARG,
    ExtensionTypeVersions_ARG,
    ExtensionProvisioningStates_ARG,
    AMA_ExtensionNames_ARG,
    AMA_ProvisioningStates_ARG,
    MDE_ExtensionNames_ARG,
    MDE_ProvisioningStates_ARG,
    AMA_Count_ARG,
    AMA_Succeeded_Count_ARG,
    MDE_Count_ARG,
    MDE_Succeeded_Count_ARG,
    ExtensionNames_Text_ARG,
    ExtensionTypes_Text_ARG
'@

        Write-Host "Executing VM_BASE_QUERY against subscriptions..." -ForegroundColor Cyan
        try {
            $vmData = Get-AllAzGraph -Query $VM_BASE_QUERY -SubscriptionId $subIds
            Write-Host ("Retrieved {0} VMs from ARG." -f $vmData.Count) -ForegroundColor Green
        }
        catch {
            Write-Error ("ARG query failed: {0}" -f $_.Exception.Message)
            $vmData = @()
        }

        # Process and index VM data
        foreach ($vm in @($vmData)) {
            if ($vm.subscriptionId) {
                $subId = [string]$vm.subscriptionId
                if (-not $vmsBySubscription[$subId]) {
                    $vmsBySubscription[$subId] = [System.Collections.Generic.List[object]]::new()
                }
                $vmsBySubscription[$subId].Add($vm)
            }

            if ($vm.id) {
                $vmId = [string]$vm.id
                $vmIndexById[$vmId] = $vm
                if ($vm.name) {
                    $vmNameById[$vmId] = [string]$vm.name
                }
            }
        }

        Add-RangeSafe -Target $AzVM_Inventory -Items $vmData
    }

    #################################
    #endregion Queries

    # Process each subscription's VMs for additional data collection (ARM calls if needed)
    foreach ($subId in @($vmsBySubscription.Keys)) {
        $vmsInSub = @($vmsBySubscription[$subId])
        
        if ($vmsInSub.Count -gt 0 -and -not $NoARM.IsPresent) {
            Write-Host ("Processing {0} VMs in subscription {1}" -f $vmsInSub.Count, $subId) -ForegroundColor Cyan
            
            # Get extension health using runspaces
            try {
                $extHealthIndex = Get-VMExtensionHealthIndexRunspace -VmRowsSub $vmsInSub -SubscriptionId $subId -TenantId $TenantId -AzContextPath $AzContextPath
                
                # Merge extension health back into inventory
                foreach ($vm in $vmsInSub) {
                    $vmId = [string]$vm.id
                    if ($extHealthIndex[$vmId]) {
                        $vm | Add-Member -MemberType NoteProperty -Name 'ExtensionHealth' -Value $extHealthIndex[$vmId] -Force
                    }
                }
            }
            catch {
                Write-Warning ("Extension health collection failed for subscription {0}: {1}" -f $subId, $_.Exception.Message)
            }
        }
    }

    # Add all processed VMs to multi-tenant inventory
    Add-RangeSafe -Target $AzVM_Inventory_multi -Items $AzVM_Inventory

    Write-Host ("Tenant {0} processing complete. VMs collected: {1}" -f $TenantDomain, $AzVM_Inventory.Count) -ForegroundColor Green

    # Ask user for repeat
    $yesOption = New-Object Management.Automation.Host.ChoiceDescription '&Yes', 'Process another tenant'
    $noOption = New-Object Management.Automation.Host.ChoiceDescription '&No', 'Exit'
    $choices = @($yesOption, $noOption)
    
    $selectedIndex = $Host.UI.PromptForChoice('Continue?', 'Process additional tenants?', $choices, 1)
    $repeat = if ($selectedIndex -eq 0) { 'Y' } else { 'N' }

} while ($repeat -eq 'Y')

Write-Host ("Grand total VMs across all tenants: {0}" -f $AzVM_Inventory_multi.Count) -ForegroundColor Green

#################################
#endregion Tenant Init and Start
