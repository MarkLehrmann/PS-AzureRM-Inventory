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
    argPowerState,
    argPowerStateCode,
    argOSName,
    argOSVersion,
    argHyperVGeneration,

    ifName_ARG = ifName_Text_ARG,
    vNet_ARG = vNet_Text_ARG,
    Subnet_ARG = Subnet_Text_ARG,
    PrivateIP_ARG = PrivateIP_Text_ARG,
    PrivateIPalloc_ARG = PrivateIPalloc_Text_ARG,

    osDiskSizeGB,
    osDiskAccessId,
    osDiskTimeCreated,
    osDiskState,
    osDiskSkuName,
    DataDiskNames_ARG = DataDiskNames_Text_ARG,
    DataDiskSizeGB_ARG,
    TotalManagedDiskSizeGB_ARG,

    ExtensionNames_ARG = ExtensionNames_Text_ARG,
    ExtensionTypes_ARG = ExtensionTypes_Text_ARG,
    ExtensionProvisioningStates_ARG,
    AMA_ExtensionNames_ARG,
    AMA_ProvisioningStates_ARG,
    MDE_ExtensionNames_ARG,
    MDE_ProvisioningStates_ARG
'@

        $NIC_QUERY = @'
Resources
| where type =~ "microsoft.network/networkinterfaces"
| extend
    ipConfigs         = properties.ipConfigurations,
    virtualMachineId  = tostring(properties.virtualMachine.id),
    privateEndpointId = tostring(properties.privateEndpoint.id),
    managedById       = tostring(managedBy)
| project id, subscriptionId, resourceGroup, name, location,
         ipConfigs, virtualMachineId, privateEndpointId, managedById
'@

        $DISK_QUERY = @'
Resources
| where type =~ "microsoft.compute/disks"
| extend
    diskSizeGB          = toint(properties.diskSizeGB),
    diskAccessId        = tostring(properties.diskAccessId),
    timeCreated         = todatetime(properties.timeCreated),
    diskState           = tostring(properties.diskState),
    managedById         = tostring(managedBy),
    skuName             = tostring(sku.name),
    osType              = tostring(properties.osType),
    lastOwnershipUpdate = todatetime(properties.LastOwnershipUpdateTime)
| project id, subscriptionId, resourceGroup, name, location,
         diskSizeGB, diskAccessId, timeCreated,
         diskState, managedById, skuName, osType, lastOwnershipUpdate
'@

        $VNET_QUERY = @'
Resources
| where type =~ "microsoft.network/virtualnetworks"
| extend subnets = parse_json(properties.subnets)
| mv-expand subnet = subnets
| extend addressPrefixArray = subnet.properties.addressPrefixes
| extend Subnet_Address = iif(
    isnull(addressPrefixArray),
    tostring(subnet.properties.addressPrefix),
    strcat_array(addressPrefixArray, " ")
)
| project
    id,
    subscriptionId,
    resourceGroup,
    name,
    location,
    vNet_Addresses = strcat_array(properties.addressSpace.addressPrefixes, " "),
    vNet_DNS       = strcat_array(properties.dhcpOptions.dnsServers, " "),
    Subnet_Name    = subnet.name,
    Subnet_Address,
    Subnet_NSG_Id  = tostring(subnet.properties.networkSecurityGroup.id),
    Route_Table_Id = tostring(subnet.properties.routeTable.id),
    vNet_Peers     = array_length(properties.virtualNetworkPeerings)
'@

        $PIP_QUERY = @'
Resources
| where type =~ "microsoft.network/publicipaddresses"
| project
    id, subscriptionId, resourceGroup, name, location,
    PublicIpAddress   = tostring(properties.ipAddress),
    AllocationMethod  = tostring(properties.publicIPAllocationMethod),
    SkuName           = tostring(sku.name),
    SkuTier           = tostring(sku.tier),
    Fqdn              = coalesce(tostring(properties.dnsSettings.fqdn), ""),
    IpConfigId        = tostring(properties.ipConfiguration.id),
    NatGatewayId      = tostring(properties.natGateway.id)
'@
        #################################
        #endregion Querie

        #region Tenant Init and Start
        #################################
        
        try {
            # --- ARG VM discovery ---
            $vmRowsArg = Get-AllAzGraph -Query $VM_BASE_QUERY -SubscriptionId $subIds -BatchSize 1000

            # --- Determine environment key (per tenant) ---
            $envKey = if ($CommercialTenant) { 'Public' } else { 'Gov' }

            # --- Build per-tenant SKU index ---
            # In NoARM mode, skip Get-AzComputeResourceSku because it is an ARM/Compute API call.
            $skuIndex = @{}

            if ($NoARM.IsPresent) {
                Write-Host "NoARM mode: skipping Compute SKU lookup. SKUvcpu, vCPUs, and MemoryGB will be marked as Skipped." -ForegroundColor Yellow
            }
            else {
                # Ensure Az.Compute is available (required for Get-AzComputeResourceSku)
                try { Import-Module Az.Compute -ErrorAction Stop | Out-Null } catch { }

                # --- Discover VM regions used by this tenant ---
                $tenantRegions = $vmRowsArg |
                Where-Object { $_.location } |
                ForEach-Object { $_.location.ToLowerInvariant() } |
                Sort-Object -Unique

                # --- Populate SKU cache (per run, per environment, additive) ---
                foreach ($region in $tenantRegions) {
                    if (-not $script:SkuCache[$envKey].Regions.ContainsKey($region)) {

                        Write-Host ("Fetching SKU data for {0} region '{1}'" -f $envKey, $region) -ForegroundColor Cyan

                        try {
                            $skuData = Get-AzComputeResourceSku -Location $region -ErrorAction Stop

                            $script:SkuCache[$envKey].Regions[$region] = $true

                            foreach ($s in @($skuData)) {
                                $script:SkuCache[$envKey].Skus.Add($s) | Out-Null
                            }
                        }
                        catch {
                            Write-Warning ("SKU lookup failed for {0} region '{1}': {2}" -f $envKey, $region, $_.Exception.Message)
                        }
                    }
                }

                foreach ($s in @($script:SkuCache[$envKey].Skus)) {
                    if (-not $s -or $s.ResourceType -ne 'virtualMachines') { continue }

                    foreach ($loc in @($s.Locations)) {
                        if (-not $loc) { continue }

                        $key = '{0}|{1}' -f $s.Name, $loc.ToLowerInvariant()
                        if (-not $skuIndex.ContainsKey($key)) {
                            $skuIndex[$key] = $s
                        }
                    }
                }

                Write-Host (
                    "SKU cache status: Env={0}, RegionsCached={1}, SKUsCached={2}, IndexKeys={3}" -f
                    $envKey,
                    $script:SkuCache[$envKey].Regions.Count,
                    $script:SkuCache[$envKey].Skus.Count,
                    $skuIndex.Count
                ) -ForegroundColor DarkGreen
            }

            # --- Remaining ARG collections ---
            $nicRowsArg = Get-AllAzGraph -Query $NIC_QUERY  -SubscriptionId $subIds -BatchSize 1000
            $diskRowsArg = Get-AllAzGraph -Query $DISK_QUERY -SubscriptionId $subIds -BatchSize 1000
            $vNetRows = Get-AllAzGraph -Query $VNET_QUERY -SubscriptionId $subIds -BatchSize 1000
            $pipRows = Get-AllAzGraph -Query $PIP_QUERY  -SubscriptionId $subIds -BatchSize 1000

            Write-Host ("ARG: VMs={0} NICs={1} Disks={2} VNets={3} PIPs={4}" -f
                $vmRowsArg.Count, $nicRowsArg.Count, $diskRowsArg.Count,
                $vNetRows.Count, $pipRows.Count) -ForegroundColor Green

            foreach ($n in $nicRowsArg) { if ($n.id) { $nicIndexById[$n.id] = $n } }
            foreach ($d in $diskRowsArg) { if ($d.id) { $diskIndexById[$d.id] = $d } }

            foreach ($vm in $vmRowsArg) {
                if ($vm.id) {
                    $vmIndexById[$vm.id] = $vm
                    $vmNameById[$vm.id] = $vm.name
                }

                if ($vm.tags) {
                    foreach ($p in $vm.tags.PSObject.Properties) {
                        $rawKey = [string]$p.Name
                        if (-not [string]::IsNullOrWhiteSpace($rawKey)) {
                            $null = $globalTagKeysRaw.Add($rawKey)
                        }
                    }
                }

                if (-not $vmsBySubscription.ContainsKey($vm.subscriptionId)) {
                    $vmsBySubscription[$vm.subscriptionId] = [System.Collections.Generic.List[object]]::new()
                }
                $vmsBySubscription[$vm.subscriptionId].Add($vm)
            }

            Write-Host ("ARG: Total discovered tag headers (global): {0}" -f $globalTagKeysRaw.Count) -ForegroundColor DarkGreen
            Write-Host ("ARG: Subscription VM buckets: {0}" -f $vmsBySubscription.Keys.Count) -ForegroundColor DarkGreen
            #################################
            #endregion Tenant Init and Start

            #region Orphaned Managed Disks / NICs (ARG reuse)
            #################################            
            try {
                

                # Build PIP lookup by Public IP resource ID for orphan NIC resolution
                $pipArgById = @{}
                foreach ($p in @($pipRows)) {
                    if ($p.id) { $pipArgById[[string]$p.id] = $p }
                }

                # --- Orphaned Managed Disks ---
                $orphanDiskCutoff = (Get-Date).AddHours(-24)

                foreach ($disk in @($diskRowsArg)) {
                    if (-not $disk) { continue }

                    $diskState = [string]$disk.diskState
                    $managedById = [string]$disk.managedById
                    $diskName = [string]$disk.name
                    $lastOwnershipUpdate = $null

                    try {
                        if ($disk.lastOwnershipUpdate) {
                            $lastOwnershipUpdate = [datetime]$disk.lastOwnershipUpdate
                        }
                    }
                    catch { }

                    $isOrphanManagedDisk =
                    ($diskState -ieq 'Unattached') -and
                    [string]::IsNullOrWhiteSpace($managedById) -and
                    ($null -eq $lastOwnershipUpdate -or $lastOwnershipUpdate -lt $orphanDiskCutoff) -and
                    (-not ($diskName -like '*-ASRReplica'))

                    if (-not $isOrphanManagedDisk) { continue }

                    $subId = [string]$disk.subscriptionId
                    $subName = if ($subscriptionNameById.ContainsKey($subId)) { $subscriptionNameById[$subId] } else { $subId }

                    $AzOrphanDisk_Inventory.Add([pscustomobject]@{
                            TenantDomain            = $TenantDomain
                            SubscriptionName        = $subName
                            ResourceGroupName       = $disk.resourceGroup
                            Location                = $disk.location
                            DiskName                = $disk.name
                            DiskType                = $disk.skuName
                            OSType                  = $disk.osType
                            DiskSizeGB              = $disk.diskSizeGB
                            TimeCreated             = if ($disk.timeCreated) { ([datetime]$disk.timeCreated).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') } else { $null }
                            LastOwnershipUpdateTime = if ($disk.lastOwnershipUpdate) { ([datetime]$disk.lastOwnershipUpdate).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') } else { $null }
                            DiskId                  = $disk.id
                        })
                }

                # --- Orphaned NICs ---
                foreach ($nic in @($nicRowsArg)) {
                    if (-not $nic) { continue }

                    $virtualMachineId = [string]$nic.virtualMachineId
                    $privateEndpointId = [string]$nic.privateEndpointId
                    $managedById = [string]$nic.managedById

                    $isOrphanNic =
                    [string]::IsNullOrWhiteSpace($virtualMachineId) -and
                    [string]::IsNullOrWhiteSpace($privateEndpointId) -and
                    [string]::IsNullOrWhiteSpace($managedById)

                    if (-not $isOrphanNic) { continue }

                    $primaryIpConfig = $null
                    $ipConfigs = @($nic.ipConfigs)

                    if ($ipConfigs.Count -gt 0) {
                        $primaryIpConfig = $ipConfigs | Where-Object { $_.properties.primary -eq $true } | Select-Object -First 1
                        if (-not $primaryIpConfig) {
                            $primaryIpConfig = $ipConfigs | Select-Object -First 1
                        }
                    }

                    $privateIp = 'na'
                    $publicIp = 'na'
                    $vnetName = 'na'
                    $subnetName = 'na'

                    if ($primaryIpConfig) {
                        if ($primaryIpConfig.properties.privateIPAddress) {
                            $privateIp = [string]$primaryIpConfig.properties.privateIPAddress
                        }

                        $subnetId = $null
                        if ($primaryIpConfig.properties.subnet -and $primaryIpConfig.properties.subnet.id) {
                            $subnetId = [string]$primaryIpConfig.properties.subnet.id
                        }

                        if (-not [string]::IsNullOrWhiteSpace($subnetId)) {
                            $vnetResolved = Get-IdSegment -Id $subnetId -SegmentName 'virtualNetworks'
                            $subnetResolved = Get-IdSegment -Id $subnetId -SegmentName 'subnets'

                            if ($vnetResolved) { $vnetName = $vnetResolved }
                            if ($subnetResolved) { $subnetName = $subnetResolved }
                        }

                        $publicIpId = $null
                        if ($primaryIpConfig.properties.publicIPAddress -and $primaryIpConfig.properties.publicIPAddress.id) {
                            $publicIpId = [string]$primaryIpConfig.properties.publicIPAddress.id
                        }

                        if ($publicIpId -and $pipArgById.ContainsKey($publicIpId)) {
                            $resolvedPip = $pipArgById[$publicIpId]
                            if ($resolvedPip.PublicIpAddress) {
                                $publicIp = [string]$resolvedPip.PublicIpAddress
                            }
                        }
                    }

                    $subId = [string]$nic.subscriptionId
                    $subName = if ($subscriptionNameById.ContainsKey($subId)) { $subscriptionNameById[$subId] } else { $subId }

                    $AzOrphanNIC_Inventory.Add([pscustomobject]@{
                            TenantDomain      = $TenantDomain
                            SubscriptionName  = $subName
                            ResourceGroupName = $nic.resourceGroup
                            Location          = $nic.location
                            NICName           = $nic.name
                            PrivateIP         = $privateIp
                            PublicIP          = $publicIp
                            VirtualNetwork    = $vnetName
                            Subnet            = $subnetName
                            NICId             = $nic.id
                        })
                }

                Write-Host ("ARG: Orphaned Managed Disks={0} Orphaned NICs={1}" -f
                    $AzOrphanDisk_Inventory.Count, $AzOrphanNIC_Inventory.Count) -ForegroundColor DarkGreen

            }
            catch {
                Write-Warning ("Orphan ARG reuse block failed: {0}" -f $_.Exception.Message)
                $AzOrphanDisk_Inventory = [System.Collections.Generic.List[object]]::new()
                $AzOrphanNIC_Inventory = [System.Collections.Generic.List[object]]::new()
            }
        }
        catch {
            Write-Warning ("ARG collection failed: {0}" -f $_.Exception.Message)
            $vmsBySubscription = @{}
            $vmIndexById = @{}
            $vmNameById = @{}
            $nicIndexById = @{}
            $diskIndexById = @{}
            $vNetRows = @()
            $pipRows = @()

            # Ensure these exist even on failure so downstream code doesn't blow up
            $vmRowsArg = @()
            $nicRowsArg = @()
            $diskRowsArg = @()
            $skuIndex = @{}
        }
    }
    else {
        Write-Warning ("No subscriptions found for tenant {0}. VM inventory will be empty." -f $Tenant)
        $vNetRows = @()
        $pipRows = @()
    }
    #################################
    #endregion Orphaned Managed Disks / NICs (ARG reuse)


    #region Subscription Loop
    #################################

    # Per subscription loop with progress + timing (ARM collectors via runspaces)
    $totalSubs = $subscription_list.Count
    $currentSub = 0
    $startTime = Get-Date

    # Progress IDs (nested progress bars)
    $progressParentId = 1
    $progressChildId = 2

    function Update-OverallProgress {
        param(
            [string]$StatusText,
            [double]$OverallPercent
        )

        $now = Get-Date
        $elapsedSoFarSec = [math]::Max(0, (New-TimeSpan -Start $startTime -End $now).TotalSeconds)

        $secsRemaining = 0
        if ($currentSub -gt 0 -and $totalSubs -gt 0) {
            $avgPerSub = $elapsedSoFarSec / $currentSub
            $secsRemaining = [int][math]::Round($avgPerSub * ($totalSubs - $currentSub))
        }

        Write-Progress -Id $progressParentId `
            -Activity "Processing Azure Subscriptions ($TenantDomain)" `
            -Status $StatusText `
            -PercentComplete $OverallPercent `
            -SecondsRemaining $secsRemaining
    }

    function Update-SubProgress {
        param(
            [string]$Phase,
            [double]$SubPercent
        )

        # Child progress bar nested under overall
        Write-Progress -Id $progressChildId -ParentId $progressParentId `
            -Activity ("Subscription {0}/{1}: {2}" -f $currentSub, $totalSubs, $subscription_name) `
            -Status $Phase `
            -PercentComplete $SubPercent
    }

    foreach ($subscription_list_iterator in $subscription_list) {
        $currentSub++
        $subscription_id = $subscription_list_iterator.Id
        $subscription_name = $subscription_list_iterator.Name

        $subStartTime = Get-Date
        $overallPercent = if ($totalSubs -gt 0) { [math]::Round(($currentSub / $totalSubs) * 100, 1) } else { 0 }

        # Overall progress (initial phase)
        Update-OverallProgress -StatusText ("Subscription {0}/{1}: {2}" -f $currentSub, $totalSubs, $subscription_name) -OverallPercent $overallPercent
        Update-SubProgress -Phase "Initializing" -SubPercent 0

        $vmRowsSub = @()
        $vmStatusIndexById = @{}
        $extHealthIndexByVmId = @{}

        try {
            # Phase: Set context
            Update-SubProgress -Phase "Setting subscription context" -SubPercent 5

            try {
                $null = Set-AzContext -Subscription $subscription_id -ErrorAction Stop
                Write-Host ("  → Processing: {0} ({1})" -f $subscription_name, $subscription_id) -ForegroundColor Cyan
            }
            catch {
                Write-Warning ("Failed to set context for subscription {0} ({1}): {2}" -f $subscription_id, $subscription_name, $_.Exception.Message)
                Update-SubProgress -Phase "Context failed; skipping subscription" -SubPercent 100
                continue
            }

            # Phase: Collect ARM resources unless NoARM mode is enabled
            Update-SubProgress -Phase "Preparing inventory collectors" -SubPercent 15

            $azureNICDetails = @()
            $azureNSGDetails = @()
            $azurePublicIPs = @()
            $AzureLBList = @()
            $vmStatusList = @()
            $vmStatusIndexById = @{}

            if ($NoARM.IsPresent) {
                Update-SubProgress -Phase "NoARM mode: skipping ARM collectors" -SubPercent 35

                Write-Host "    NoARM mode: skipped ARM collectors for NIC/NSG/PIP/LB/VM status." -ForegroundColor Yellow
            }
            else {
                Update-SubProgress -Phase "Running collectors (NIC/NSG/PIP/LB/VM Status)" -SubPercent 15

                $collectorJobs = @(
                    @{ Name = 'NIC'; JobType = 'NIC'; SubscriptionId = $subscription_id },
                    @{ Name = 'NSG'; JobType = 'NSG'; SubscriptionId = $subscription_id },
                    @{ Name = 'PIP'; JobType = 'PIP'; SubscriptionId = $subscription_id },
                    @{ Name = 'LB'; JobType = 'LB'; SubscriptionId = $subscription_id },
                    @{ Name = 'VMSTATUS'; JobType = 'VMSTATUS'; SubscriptionId = $subscription_id }
                )

                $collectorThrottle = [Math]::Min(8, [Math]::Max(2, $MaxConcurrency))
                $collectorResults = Invoke-RunspaceBatch -Jobs $collectorJobs -Throttle $collectorThrottle -TenantId $TenantId -AzContextPath $AzContextPath

                Update-SubProgress -Phase "Collectors complete; indexing results" -SubPercent 35

                foreach ($r in $collectorResults) {
                    if (-not $r.Ok -and $r.Error) {
                        Write-Warning ("  Collector {0} failed in {1}: {2}" -f $r.Name, $subscription_name, $r.Error)
                    }

                    switch ($r.Name) {
                        'NIC' { $azureNICDetails = @($r.Data) }
                        'NSG' { $azureNSGDetails = @($r.Data) }
                        'PIP' { $azurePublicIPs = @($r.Data) }
                        'LB' { $AzureLBList = @($r.Data) }
                        'VMSTATUS' { $vmStatusList = @($r.Data) }
                    }
                }

                foreach ($vmS in $vmStatusList) {
                    if ($vmS.Id) { $vmStatusIndexById[$vmS.Id] = $vmS }
                }
            }

            # Phase: Determine VMs in this subscription (from ARG bucket)
            Update-SubProgress -Phase "Resolving VMs discovered via ARG" -SubPercent 45

            $vmRowsSub = if ($vmsBySubscription.ContainsKey($subscription_id)) { $vmsBySubscription[$subscription_id] } else { @() }

            if (-not $vmRowsSub -or $vmRowsSub.Count -eq 0) {
                Write-Host ("    No VMs found in subscription {0} ({1}) via ARG." -f $subscription_id, $subscription_name) -ForegroundColor Yellow
                Update-SubProgress -Phase "No VMs; skipping extension health" -SubPercent 60
            }
            else {
                if ($NoARM.IsPresent) {
                    $extHealthIndexByVmId = @{}

                    Update-SubProgress -Phase "NoARM mode: skipping VM extension health checks" -SubPercent 75
                    Write-Host "    NoARM mode: skipped VM extension health checks. Agent fields will be marked as Skipped." -ForegroundColor Yellow
                }
                else {
                    # Phase: Extension health (per-VM runspaces) with mini heartbeat via chunking
                    $extThrottle = [Math]::Min(16, [Math]::Max(4, $MaxConcurrency))

                    # Chunk size: smaller chunks = more frequent progress updates (mini heartbeat)
                    $chunkSize = [Math]::Max(25, [Math]::Min(75, $extThrottle * 5))

                    $totalVms = $vmRowsSub.Count
                    $processed = 0

                    Update-SubProgress -Phase ("Checking VM extensions (0/{0}, throttle={1})" -f $totalVms, $extThrottle) -SubPercent 55

                    $extHealthIndexByVmId = @{}

                    for ($i = 0; $i -lt $totalVms; $i += $chunkSize) {
                        $take = [Math]::Min($chunkSize, $totalVms - $i)
                        $chunk = @($vmRowsSub[$i..($i + $take - 1)])

                        $processedText = "{0}/{1}" -f $processed, $totalVms
                        $subPct = 55 + ([math]::Round((($processed / [double]$totalVms) * 20), 1))
                        Update-SubProgress -Phase ("Checking VM extensions ({0}, throttle={1})" -f $processedText, $extThrottle) -SubPercent $subPct

                        $chunkIndex = Get-VMExtensionHealthIndexRunspace `
                            -VmRowsSub $chunk `
                            -SubscriptionId $subscription_id `
                            -TenantId $TenantId `
                            -AzContextPath $AzContextPath `
                            -Throttle $extThrottle

                        if ($chunkIndex) {
                            foreach ($k in $chunkIndex.Keys) {
                                $extHealthIndexByVmId[[string]$k] = $chunkIndex[$k]
                            }
                        }

                        $processed += $take
                    }

                    Update-SubProgress -Phase ("Extension health complete ({0}/{1})" -f $processed, $totalVms) -SubPercent 75
                }



                #region Virtual Machine Details (ARG-first)
                #################################

                Update-SubProgress -Phase "Building VM inventory objects" -SubPercent 85

                $virtual_machine_object = [System.Collections.Generic.List[object]]::new()

                foreach ($vm in $vmRowsSub) {

                    ###########################################################################
                    # VM status / agent / extension state
                    ###########################################################################

                    $vm_status = $null
                    if (-not $NoARM.IsPresent -and $vm.id -and $vmStatusIndexById.ContainsKey($vm.id)) {
                        $vm_status = $vmStatusIndexById[$vm.id]
                    }

                    if ($NoARM.IsPresent) {
                        # ARG-only mode:
                        # VMStatus_ARG, VM_Agent_Status_ARG, AzureMonitorAgent_ARG, and MDEAgent_ARG
                        # are produced by the expanded ARG VM query.
                        $powerState = if ($vm.VMStatus_ARG) {
                            [string]$vm.VMStatus_ARG
                        }
                        else {
                            'ARG:NotReported'
                        }

                        $vmAgentStatus = if ($vm.VM_Agent_Status_ARG) {
                            [string]$vm.VM_Agent_Status_ARG
                        }
                        else {
                            'ARG:NotAvailable'
                        }

                        $amaStatus = if ($vm.AzureMonitorAgent_ARG) {
                            [string]$vm.AzureMonitorAgent_ARG
                        }
                        else {
                            'Not Installed'
                        }

                        $mdeStatus = if ($vm.MDEAgent_ARG) {
                            [string]$vm.MDEAgent_ARG
                        }
                        else {
                            'Not Installed'
                        }
                    }
                    else {
                        # Full mode:
                        # Use ARM Get-AzVM -Status and Get-AzVMExtension augmentation.
                        $powerState = 'Unknown'

                        if ($vm_status) {
                            if ($vm_status.PSObject.Properties.Name -contains 'PowerState' -and $vm_status.PowerState) {
                                $powerState = [string]$vm_status.PowerState
                            }
                            else {
                                $ps = $vm_status.Statuses |
                                Where-Object { $_.Code -like 'PowerState/*' } |
                                Select-Object -First 1

                                if ($ps) {
                                    $powerState = if ($ps.DisplayStatus) {
                                        [string]$ps.DisplayStatus
                                    }
                                    else {
                                        [string]$ps.Code
                                    }
                                }
                            }
                        }

                        $vmAgentStatus = 'Unknown'
                        $amaStatus = 'Not Installed'
                        $mdeStatus = 'Not Installed'

                        if ($vm.id -and $extHealthIndexByVmId.ContainsKey([string]$vm.id)) {
                            $eh = $extHealthIndexByVmId[[string]$vm.id]

                            if ($eh.VM_Agent_Status) {
                                $vmAgentStatus = [string]$eh.VM_Agent_Status
                            }

                            if ($eh.AzureMonitorAgent) {
                                $amaStatus = [string]$eh.AzureMonitorAgent
                            }

                            if ($eh.MDEAgent) {
                                $mdeStatus = [string]$eh.MDEAgent
                            }
                        }
                    }

                    ###########################################################################
                    # VM size / SKU enrichment
                    ###########################################################################

                    $vmSize = [string]$vm.vmSize
                    $location = [string]$vm.location
                    $locationKey = if ($location) { $location.ToLowerInvariant() } else { '' }
                    $skuKey = '{0}|{1}' -f $vmSize, $locationKey

                    if ($NoARM.IsPresent) {
                        # ARG does not expose the VM SKU capability catalog.
                        # Keep these explicit and audit-friendly.
                        $vcpuBase = 'ARG:NotAvailable'
                        $vcpuAvail = 'ARG:NotAvailable'
                        $memory = 'ARG:NotAvailable'
                    }
                    else {
                        $vcpuBase = 'Unknown'
                        $vcpuAvail = 'Unknown'
                        $memory = 'Unknown'

                        if ($skuIndex.ContainsKey($skuKey)) {
                            $sku = $skuIndex[$skuKey]

                            $vcpuBase = ($sku.Capabilities | Where-Object Name -eq 'vCPUs').Value
                            $vcpuAvail = ($sku.Capabilities | Where-Object Name -eq 'vCPUsAvailable').Value
                            $memory = ($sku.Capabilities | Where-Object Name -eq 'MemoryGB').Value

                            if (-not $vcpuAvail) {
                                $vcpuAvail = $vcpuBase
                            }
                        }
                    }

                    ###########################################################################
                    # Placement metadata
                    ###########################################################################

                    $vm_zone = if ($vm.zones) {
                        $vm.zones -join '; '
                    }
                    else {
                        'Non-zonal'
                    }

                    $vm_set = 'None'
                    if ($vm.availSetId) {
                        $vm_set = ([string]$vm.availSetId -split '/')[-1]
                    }

                    ###########################################################################
                    # NIC / IP / subnet resolution
                    ###########################################################################

                    $ifName = ''
                    $vNet = ''
                    $subnet = ''
                    $privateIp = ''
                    $privateIpAlloc = ''

                    if ($NoARM.IsPresent) {
                        # ARG-only mode:
                        # These are already flattened by the expanded VM_BASE_QUERY.
                        $ifName = if ($vm.ifName_ARG) { [string]$vm.ifName_ARG } else { '' }
                        $vNet = if ($vm.vNet_ARG) { [string]$vm.vNet_ARG } else { '' }
                        $subnet = if ($vm.Subnet_ARG) { [string]$vm.Subnet_ARG } else { '' }
                        $privateIp = if ($vm.PrivateIP_ARG) { [string]$vm.PrivateIP_ARG } else { '' }
                        $privateIpAlloc = if ($vm.PrivateIPalloc_ARG) { [string]$vm.PrivateIPalloc_ARG } else { '' }
                    }
                    else {
                        # Full mode:
                        # Preserve existing ARM/ARG hybrid NIC lookup behavior.
                        $vm_ip_details = [System.Collections.Generic.List[object]]::new()

                        foreach ($nicRef in @($vm.nicRefs)) {
                            $nicId = [string]$nicRef.id

                            if (-not $nicId) {
                                continue
                            }

                            if (-not $nicIndexById.ContainsKey($nicId)) {
                                continue
                            }

                            $nic = $nicIndexById[$nicId]

                            foreach ($ipConfig in @($nic.ipConfigs)) {
                                $subnetId = $null

                                if ($ipConfig.properties -and $ipConfig.properties.subnet -and $ipConfig.properties.subnet.id) {
                                    $subnetId = [string]$ipConfig.properties.subnet.id
                                }

                                $vnetName = $null
                                $subnetName = $null

                                if (-not [string]::IsNullOrWhiteSpace($subnetId)) {
                                    $vnetName = Get-IdSegment -Id $subnetId -SegmentName 'virtualNetworks'
                                    $subnetName = Get-IdSegment -Id $subnetId -SegmentName 'subnets'
                                }

                                $vm_ip_details.Add([pscustomobject]@{
                                        ifName     = $nic.name
                                        PrivateIP  = $ipConfig.properties.privateIPAddress
                                        Allocation = $ipConfig.properties.privateIPAllocationMethod
                                        VNet       = $vnetName
                                        Subnet     = $subnetName
                                        Primary    = $ipConfig.properties.primary
                                    })
                            }
                        }

                        $ifName = (($vm_ip_details.ifName | Select-Object -Unique) -join ';')
                        $vNet = (($vm_ip_details.VNet | Where-Object { $_ } | Select-Object -Unique) -join ';')
                        $subnet = (($vm_ip_details.Subnet | Where-Object { $_ } | Select-Object -Unique) -join ';')
                        $privateIp = (($vm_ip_details.PrivateIP | Where-Object { $_ } | Select-Object -Unique) -join ';')
                        $privateIpAlloc = (($vm_ip_details.Allocation | Where-Object { $_ } | Select-Object -Unique) -join ';')
                    }

                    ###########################################################################
                    # Disk resolution
                    ###########################################################################

                    $OSdiskAccessId = 'NA'
                    $os_disk_size_gb = 0
                    $total_disk_size_gb = 0
                    $dataDiskNames = @()

                    $osDiskId = [string]$vm.osDiskManagedId
                    $osDisk = $null

                    if ($NoARM.IsPresent) {
                        # ARG-only mode:
                        # Disk values are already joined into the expanded VM_BASE_QUERY.
                        if ($vm.osDiskAccessId) {
                            $OSdiskAccessId = [string]$vm.osDiskAccessId
                        }

                        if ($vm.osDiskSizeGB -ne $null -and [string]$vm.osDiskSizeGB -ne '') {
                            try {
                                $os_disk_size_gb = [int]$vm.osDiskSizeGB
                            }
                            catch {
                                $os_disk_size_gb = 0
                            }
                        }

                        if ($vm.TotalManagedDiskSizeGB_ARG -ne $null -and [string]$vm.TotalManagedDiskSizeGB_ARG -ne '') {
                            try {
                                $total_disk_size_gb = [int64]$vm.TotalManagedDiskSizeGB_ARG
                            }
                            catch {
                                $total_disk_size_gb = $os_disk_size_gb
                            }
                        }
                        else {
                            $total_disk_size_gb = $os_disk_size_gb
                        }

                        if ($vm.DataDiskNames_ARG) {
                            $dataDiskNames = @(([string]$vm.DataDiskNames_ARG) -split ';' | Where-Object { $_ })
                        }

                        if ($osDiskId) {
                            $os_disk_details_managed = $osDiskId
                            $os_disk_details_unmanaged = 'Managed OS Disk'
                        }
                        else {
                            $os_disk_details_managed = 'Unmanaged OS Disk'
                            $os_disk_details_unmanaged = if ($vm.osDiskVhdUri) {
                                [string]$vm.osDiskVhdUri
                            }
                            else {
                                $null
                            }
                        }
                    }
                    else {
                        # Full mode:
                        # Preserve existing disk processing against ARG disk index.
                        if ($osDiskId -and $diskIndexById.ContainsKey($osDiskId)) {
                            $osDisk = $diskIndexById[$osDiskId]
                        }

                        if ($osDiskId) {
                            $os_disk_details_managed = $osDiskId
                            $os_disk_details_unmanaged = 'Managed OS Disk'

                            if ($osDisk) {
                                $os_disk_size_gb = [int]$osDisk.diskSizeGB

                                if ($osDisk.diskAccessId) {
                                    $OSdiskAccessId = $osDisk.diskAccessId
                                }
                            }
                        }
                        else {
                            $os_disk_details_unmanaged = $vm.osDiskVhdUri
                            $os_disk_details_managed = 'Unmanaged OS Disk'
                        }

                        $dataDiskNames = @()
                        $total_disk_size_gb = $os_disk_size_gb

                        foreach ($dd in @($vm.dataDisks)) {
                            if (-not $dd) {
                                continue
                            }

                            $ddName = [string]$dd.name
                            $ddId = [string]$dd.managedDisk.id

                            if ($ddName) {
                                $dataDiskNames += $ddName
                            }

                            if ($ddId -and $diskIndexById.ContainsKey($ddId)) {
                                $total_disk_size_gb += [int]$diskIndexById[$ddId].diskSizeGB
                            }
                        }
                    }

                    ###########################################################################
                    # OS creation / OS guest details
                    ###########################################################################

                    $osCreation = 'NA'

                    if ($vm.timeCreated) {
                        try {
                            $osCreation = ([datetime]$vm.timeCreated).ToString('yyyy-MM-dd')
                        }
                        catch {
                            $osCreation = 'NA'
                        }
                    }
                    elseif ($NoARM.IsPresent -and $vm.osDiskTimeCreated) {
                        try {
                            $osCreation = ([datetime]$vm.osDiskTimeCreated).ToString('yyyy-MM-dd')
                        }
                        catch {
                            $osCreation = 'NA'
                        }
                    }
                    elseif (-not $NoARM.IsPresent -and $osDisk -and $osDisk.timeCreated) {
                        try {
                            $osCreation = ([datetime]$osDisk.timeCreated).ToString('yyyy-MM-dd')
                        }
                        catch {
                            $osCreation = 'NA'
                        }
                    }

                    if ($NoARM.IsPresent) {
                        $osName = if ($vm.argOSName) {
                            [string]$vm.argOSName
                        }
                        else {
                            'ARG:NotReported'
                        }

                        $osVersion = if ($vm.argOSVersion) {
                            [string]$vm.argOSVersion
                        }
                        else {
                            'ARG:NotReported'
                        }
                    }
                    else {
                        $osName = if ($vm_status -and $vm_status.PSObject.Properties.Name -contains 'OsName') {
                            [string]$vm_status.OsName
                        }
                        else {
                            $null
                        }

                        $osVersion = if ($vm_status -and $vm_status.PSObject.Properties.Name -contains 'OsVersion') {
                            [string]$vm_status.OsVersion
                        }
                        else {
                            $null
                        }
                    }

                    ###########################################################################
                    # Final VM object
                    ###########################################################################

                    $vmObject = [ordered]@{
                        TenantDomain           = $TenantDomain
                        SubscriptionName       = $subscription_name
                        ResourceGroupName      = $vm.resourceGroup
                        Location               = $location
                        VMName                 = $vm.name
                        VMStatus               = $powerState
                        VMSize                 = $vmSize
                        SKUvcpu                = $vcpuBase
                        vCPUs                  = $vcpuAvail
                        MemoryGB               = $memory
                        Zone                   = $vm_zone
                        Set                    = $vm_set
                        VM_Agent_Status        = $vmAgentStatus
                        AzureMonitorAgent      = $amaStatus
                        MDEAgent               = $mdeStatus
                        ifName                 = $ifName
                        vNet                   = $vNet
                        Subnet                 = $subnet
                        PrivateIP              = $privateIp
                        PrivateIPalloc         = $privateIpAlloc
                        LicenseType            = $vm.licenseType
                        OSName                 = $osName
                        OSVersion              = $osVersion
                        OSType                 = $vm.osType
                        OSImagePub             = $vm.imagePub
                        OSImageSku             = $vm.imageSku
                        OSDate                 = $osCreation
                        AdminUserName          = $vm.adminUser
                        OSDiskAccessId         = $OSdiskAccessId
                        ManagedOSDiskURI       = $os_disk_details_managed
                        ManagedOSDiskSizeGB    = $os_disk_size_gb
                        TotalManagedDiskSizeGB = $total_disk_size_gb
                        UnManagedOSDiskURI     = $os_disk_details_unmanaged
                        DataDiskNames          = ($dataDiskNames -join ';')
                    }

                    ###########################################################################
                    # Raw tag preservation for global tag header normalization
                    ###########################################################################

                    $vmTagTable = @{}

                    if ($vm.Tags) {
                        foreach ($p in $vm.Tags.PSObject.Properties) {
                            $vmTagTable[$p.Name] = $p.Value
                        }
                    }

                    $vmObject['_TagTable'] = $vmTagTable

                    $virtual_machine_object.Add([pscustomobject]$vmObject)
                }

                Add-RangeSafe -Target $AzVM_Inventory -Items $virtual_machine_object

                #################################
                #endregion Virtual Machine Details (ARG-first)

            $Azure_NSG_output = foreach ($azureNSGDetails_Iterator in $azureNSGDetails) {
                $securityRulesPerNSG = $azureNSGDetails_Iterator.SecurityRules

                $NSG_NICs = foreach ($NSG_NIC_ID in $azureNSGDetails_Iterator.NetworkInterfaces.Id) {
                    $azureNICDetails.Where({ $_.Id -eq $NSG_NIC_ID })
                }

                $NSG_NICs_VMs = foreach ($NSG_NIC in $NSG_NICs) {
                    $vmId = $null
                    try { $vmId = [string]$NSG_NIC.VirtualMachine.Id } catch { $vmId = $null }
                    if ($vmId -and $vmNameById.ContainsKey($vmId)) { $vmNameById[$vmId] }
                }

                $NSG_NICs_PIP = foreach ($IP_Conf_Id in $NSG_NICs.IpConfigurations.Id) {
                    $azurePublicIPs.Where({ $_.IpConfiguration.Id -eq $IP_Conf_Id })
                }

                $NSG_Subnets = foreach ($Subnet_Iterator in $azureNSGDetails_Iterator.Subnets) {
                    $Subnet_Iterator.Id.Split('/') | Select-Object -Last 1
                }

                foreach ($securityRulesPerNSG_Iterator in $securityRulesPerNSG) {
                    [pscustomobject]@{
                        TenantDomain             = $TenantDomain
                        Subscription             = $subscription_name
                        Resourc_Group            = $azureNSGDetails_Iterator.ResourceGroupName
                        Location                 = $azureNSGDetails_Iterator.Location
                        NSG_Name                 = $azureNSGDetails_Iterator.Name
                        Rule_Name                = $securityRulesPerNSG_Iterator.Name
                        Priority                 = $securityRulesPerNSG_Iterator.Priority
                        Protocol                 = $securityRulesPerNSG_Iterator.Protocol
                        Direction                = $securityRulesPerNSG_Iterator.Direction
                        SourcePortRange          = ($securityRulesPerNSG_Iterator | Select-Object @{ Name = 'SPR'; Expression = { $_.SourcePortRange } }).SPR
                        DestinationPortRange     = ($securityRulesPerNSG_Iterator | Select-Object @{ Name = 'DPR'; Expression = { $_.DestinationPortRange } }).DPR
                        SourceAddressPrefix      = ($securityRulesPerNSG_Iterator | Select-Object @{ Name = 'SAP'; Expression = { $_.SourceAddressPrefix } }).SAP
                        DestinationAddressPrefix = ($securityRulesPerNSG_Iterator | Select-Object @{ Name = 'DAP'; Expression = { $_.DestinationAddressPrefix } }).DAP
                        Access                   = $securityRulesPerNSG_Iterator.Access
                        'NSG VMs'                = (($NSG_NICs_VMs) -join ';')
                        'NSG NICs'               = (($NSG_NICs.Name) -join ';')
                        'NSG NIC IP'             = (($NSG_NICs.IpConfigurations.PrivateIpAddress) -join ';')
                        'NSG NIC PIP'            = (($NSG_NICs_PIP.IpAddress) -join ';')
                        'NSG Subnets'            = (($NSG_Subnets) -join ';')
                        Description              = $securityRulesPerNSG_Iterator.Description
                    }
                }
            }

            Add-RangeSafe -Target $AzNSG_Inventory -Items $Azure_NSG_output
            #################################
            #endregion Network Security Groups Details
            #region Virtual Network Details (from tenant ARG)

            $Output_vNets = foreach ($vnetRow in ($vNetRows | Where-Object { $_.subscriptionId -eq $subscription_id })) {
                [pscustomobject]@{
                    TenantDomain   = $TenantDomain
                    Subscription   = $subscription_name
                    Resourc_Group  = $vnetRow.resourceGroup
                    Location       = $vnetRow.location
                    Virtual_Net    = $vnetRow.name
                    vNet_Addresses = $vnetRow.vNet_Addresses
                    vNet_DNS       = if ([string]::IsNullOrWhiteSpace([string]$vnetRow.vNet_DNS)) { 'AzureDefault' } else { [string]$vnetRow.vNet_DNS }
                    Subnet_Name    = $vnetRow.Subnet_Name
                    Subnet_Address = $vnetRow.Subnet_Address
                    Subnet_NSG     = if ($vnetRow.Subnet_NSG_Id) { ($vnetRow.Subnet_NSG_Id -split '/')[-1] } else { 'None' }
                    Route_Table    = if ($vnetRow.Route_Table_Id) { ($vnetRow.Route_Table_Id -split '/')[-1] } else { 'None' }
                    vNet_Peers     = $vnetRow.vNet_Peers
                }
            }

            Add-RangeSafe -Target $AzvNet_Inventory -Items $Output_vNets

            #endregion Virtual Network Details (from tenant ARG)
            #region Public IP Details (from tenant ARG)
            #################################
            $Output_PIP = foreach ($pip in $pipRows | Where-Object { $_.subscriptionId -eq $subscription_id }) {
                $OwnerType = 'Not Associated'
                $OwnerName = 'None'
                $IpConfiguration = 'None'
                $NetworkIf = 'None'
                $InternalIP = 'None'

                if ($pip.IpConfigId) {
                    $parts = $pip.IpConfigId -split '/'
                    $OwnerType = $parts[-4]
                    $OwnerName = $parts[-3]
                    $IpConfiguration = $parts[-1]

                    $nicIdFromIpCfg = ($pip.IpConfigId -replace '/ipConfigurations/.+$', '')
                    if ($OwnerType -eq 'networkInterfaces' -and $nicIndexById.ContainsKey($nicIdFromIpCfg)) {
                        $nic = $nicIndexById[$nicIdFromIpCfg]
                        $NetworkIf = $nic.name
                        $InternalIP = ($nic.ipConfigs | Where-Object { $_.properties.publicIPAddress.id -eq $pip.id }).properties.privateIPAddress
                    }
                }
                elseif ($pip.NatGatewayId) {
                    $parts = $pip.NatGatewayId -split '/'
                    $OwnerType = 'natGateways'
                    $OwnerName = $parts[-1]
                    $IpConfiguration = 'NatGateway'
                }

                [pscustomobject]@{
                    TenantDomain      = $TenantDomain
                    Subscription      = $subscription_name
                    Resourc_Group     = $pip.resourceGroup
                    Location          = $pip.location
                    Name              = $pip.name
                    PublicIpAddress   = $pip.PublicIpAddress
                    FQDN              = $pip.Fqdn
                    SKU               = $pip.SkuName
                    AllocationMethod  = $pip.AllocationMethod
                    OwnerType         = $OwnerType
                    OwnerName         = $OwnerName
                    IpConfiguration   = $IpConfiguration
                    NetworkInterface  = $NetworkIf
                    InternalIpAddress = $InternalIP
                }
            }

            Add-RangeSafe -Target $AzPIP_Inventory -Items $Output_PIP
            #################################
            #endregion Public IP Details
            #region Load Balancer Details
            #################################

            $azure_load_balancer_object = [System.Collections.Generic.List[object]]::new()

            # Index Public IPs by resource ID for quick resolution
            $pipById = @{}
            foreach ($p in @($azurePublicIPs)) {
                if ($p -and $p.Id) { $pipById[[string]$p.Id] = $p }
            }

            foreach ($lb in @($AzureLBList)) {
                $feNames = @($lb.FrontendIpConfigurations | ForEach-Object { $_.Name } | Where-Object { $_ })
                $beNames = @($lb.BackendAddressPools      | ForEach-Object { $_.Name } | Where-Object { $_ })

                # Collect all frontend IPs (private and/or public) into one list
                $frontendIps = [System.Collections.Generic.List[string]]::new()

                foreach ($fe in @($lb.FrontendIpConfigurations)) {
                    if (-not $fe) { continue }

                    if ($fe.PrivateIpAddress) {
                        $frontendIps.Add([string]$fe.PrivateIpAddress)
                    }

                    if ($fe.PublicIpAddress -and $fe.PublicIpAddress.Id) {
                        $pubid = [string]$fe.PublicIpAddress.Id
                        if ($pipById.ContainsKey($pubid) -and $pipById[$pubid].IpAddress) {
                            $frontendIps.Add([string]$pipById[$pubid].IpAddress)
                        }
                        else {
                            $frontendIps.Add(('PIP:' + (($pubid -split '/')[-1])))
                        }
                    }
                }

                $frontendIpText = ($frontendIps | Where-Object { $_ } | Select-Object -Unique) -join ';'

                $azure_load_balancer_object.Add([pscustomobject]@{
                        Tenant                       = $TenantDomain
                        Subscription                 = $subscription_name
                        ResourceGroupName            = $lb.ResourceGroupName
                        Name                         = $lb.Name
                        PrivateIP                    = $frontendIpText
                        Location                     = $lb.Location
                        FrontendIpConfigurationsName = (($feNames | Select-Object -Unique) -join ';')
                        BackendAddressPoolsName      = (($beNames | Select-Object -Unique) -join ';')
                    })
            }

            Add-RangeSafe -Target $AzLBe_Inventory -Items $azure_load_balancer_object
            #################################
            #endregion Load Balancer Details

            Update-SubProgress -Phase "Subscription processing complete" -SubPercent 100
        }
        catch {
            Write-Warning ("  ✗ FAILED subscription '{0}': {1}" -f $subscription_name, $_.Exception.Message)
            Update-SubProgress -Phase "Failed" -SubPercent 100
        }
        finally {
            $subElapsed = (Get-Date) - $subStartTime
            $vmCount = if ($vmRowsSub) { $vmRowsSub.Count } else { 0 }
            Write-Host ("    ✓ Complete [{0:mm\:ss}] ({1:N0} VMs)" -f $subElapsed, $vmCount) -ForegroundColor Green

            # Clear child progress for the next subscription
            Write-Progress -Id $progressChildId -ParentId $progressParentId -Activity " " -Completed
        }
    }


    
    $totalElapsed = (Get-Date) - $startTime
    Write-Progress -Activity "Processing Azure Subscriptions" -Completed
    Write-Host "`n🎉 TOTAL RUNTIME: $($totalElapsed.ToString('hh\:mm\:ss')) for $totalSubs subscriptions" -ForegroundColor Magenta

    Add-RangeSafe -Target $AzVM_Inventory_multi   -Items $AzVM_Inventory
    Add-RangeSafe -Target $AzNSG_Inventory_multi  -Items $AzNSG_Inventory
    Add-RangeSafe -Target $AzvNet_Inventory_multi -Items $AzvNet_Inventory
    Add-RangeSafe -Target $AzPIP_Inventory_multi  -Items $AzPIP_Inventory
    Add-RangeSafe -Target $AzLBe_Inventory_multi  -Items $AzLBe_Inventory
    Add-RangeSafe -Target $AzOrphanDisk_Inventory_multi -Items $AzOrphanDisk_Inventory
    Add-RangeSafe -Target $AzOrphanNIC_Inventory_multi  -Items $AzOrphanNIC_Inventory

    try {
        if ($AzContextPath -and (Test-Path $AzContextPath)) {
            Remove-Item -Path $AzContextPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch { }

    do {
        $repeat = (Read-Host 'Do you want to repeat the script? (Y/N)').ToUpperInvariant()
    } while ($repeat -notin @('Y', 'N'))

} while ($repeat -eq 'Y')
#################################
#endregion Subscription Loop

#region Build and Export
#################################

# Build global tag header list once (after all tenants)
$globalTagHeaderList = @($globalTagKeysRaw) | Sort-Object
Write-Host ("Final global tag headers: {0}" -f $globalTagHeaderList.Count) -ForegroundColor Green

# Normalize VM inventory to include global tag columns consistently
$AzVM_Inventory_multi_export = [System.Collections.Generic.List[object]]::new()

# Capture base VM property names to prevent overwrite
$baseNameSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

if ($AzVM_Inventory_multi.Count -gt 0) {
    foreach ($n in ($AzVM_Inventory_multi[0].PSObject.Properties.Name | Where-Object { $_ -ne '_TagTable' })) {
        [void]$baseNameSet.Add([string]$n)
    }
}

foreach ($rec in $AzVM_Inventory_multi) {

    $out = [ordered]@{}

    # Copy base VM properties exactly as generated
    foreach ($p in $rec.PSObject.Properties) {
        if ($p.Name -ne '_TagTable') {
            $out[$p.Name] = $p.Value
        }
    }

    $vmTagTable = $rec._TagTable
    if ($null -eq $vmTagTable) { $vmTagTable = @{} }

    foreach ($tagKey in $globalTagHeaderList) {

        $rawKey = [string]$tagKey
        if ([string]::IsNullOrEmpty($rawKey)) { continue }

        # EXACT requested naming: Tag_ + raw tag key (spaces/case preserved)
        $colName = "Tag_{0}" -f $rawKey

        # Guard against the extremely rare case of a header collision
        if ($baseNameSet.Contains($colName) -or $out.Contains($colName)) {
            $i = 1
            $candidate = "{0}_{1}" -f $colName, $i
            while ($baseNameSet.Contains($candidate) -or $out.Contains($candidate)) {
                $i++
                $candidate = "{0}_{1}" -f $colName, $i
            }
            # Write-Warning ("Tag column name collision detected for '{0}'. Exporting as '{1}'." -f $colName, $candidate)
            $colName = $candidate
        }

        $value = $null
        if ($vmTagTable.ContainsKey($rawKey)) {
            $value = $vmTagTable[$rawKey]
        }

        $out[$colName] = if ([string]::IsNullOrWhiteSpace([string]$value)) {
            'N/A'
        }
        else {
            $value
        }
    }

    $AzVM_Inventory_multi_export.Add([pscustomobject]$out)
}

# Exporting inventory data (single folder output)
try {
    if (-not $script:RunOutputFolder -or -not (Test-Path $script:RunOutputFolder)) {
        throw "RunOutputFolder is not set or does not exist. Cannot export."
    }

    Set-Location $script:RunOutputFolder

    if ($AzVM_Inventory_multi_export.Count -gt 0) {
        $AzVM_Inventory_multi_export | Export-Csv (('{0}{1}.csv' -f $CSV_VM_name, $runStampText)) -NoTypeInformation -Force
    }
    if ($AzNSG_Inventory_multi.Count -gt 0) { $AzNSG_Inventory_multi  | Export-Csv (("NSG_Custom_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }
    if ($AzvNet_Inventory_multi.Count -gt 0) { $AzvNet_Inventory_multi | Export-Csv (("vNet_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }
    if ($AzPIP_Inventory_multi.Count -gt 0) { $AzPIP_Inventory_multi  | Export-Csv (("PIP_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }
    if ($AzLBe_Inventory_multi.Count -gt 0) { $AzLBe_Inventory_multi  | Export-Csv (("LBe_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }
    if ($AzOrphanDisk_Inventory_multi.Count -gt 0) { $AzOrphanDisk_Inventory_multi | Export-Csv (("Orphan_Disk_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }
    if ($AzOrphanNIC_Inventory_multi.Count -gt 0) { $AzOrphanNIC_Inventory_multi  | Export-Csv (("Orphan_NIC_{0}.csv" -f $runStampText)) -NoTypeInformation -Force }


    Write-Host ("Inventory exported to: {0}" -f $script:RunOutputFolder) -ForegroundColor Green
}
finally {
    Set-Location $originalLocation
}
#################################
#endregion Build and Export