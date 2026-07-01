<#
.SYNOPSIS
    Azure Multi-Tenant, ARG-First Azure Inventory Collector

.DESCRIPTION
    Collects comprehensive Azure resource inventory across one or more tenants using
    an ARG-first discovery model with ARM augmentation where required.

    Primary discovery is performed via Azure Resource Graph (ARG) for scale and speed,
    with targeted ARM calls used only where required.

    ARG is used as the authoritative source for:
    • Virtual Machines (core properties, disks, NIC references, image metadata)
    • Network Interfaces (IP configuration and VM association)
    • Network Security Groups (rules, NIC and subnet associations)
    • Virtual Networks and subnets
    • Public IP Addresses
    • Managed Disks

    Targeted ARM calls are reserved for data not reliably available via ARG:
    • VM power state and runtime OS details (instance view)
    • VM extension and agent health
    • Load Balancers (frontend and backend configuration topology)

    This hybrid model enables high performance, tenant-wide discovery via ARG,
    while preserving accuracy for runtime and platform-specific details via ARM.


    Inventory is collected per tenant, across all enabled subscriptions, and exported
    as normalized CSV files into a single timestamped output folder.

    RESOURCE COVERAGE:
    • Virtual Machines
        - Power state and OS name/version (ARG where available; ARM for full fidelity)
        - SKU (vCPU / Memory via cached SKU index)
        - Availability Zone / Set
        - NIC, subnet, and private IP mapping (ARG-based)
        - VM Agent, Azure Monitor Agent, MDE health (ARM augmentation)
        - Managed & unmanaged disk sizing (ARG-based)
        - Full raw tag capture with global normalization

    • Network Security Groups
        - Security rules (one rule per row)
        - NIC and subnet associations (resolved via ARG NIC graph)
        - VM and IP correlation via NIC relationships (ARG-based)

    • Virtual Networks
        - Address spaces and subnets
        - NSG and route table references

    • Public IP Addresses
        - Allocation method, SKU, and FQDN
        - NIC and NAT Gateway association (ARG-based resolution)

    • Load Balancers
        - Frontend IPs (public and private)
        - Backend address pools
        - Backend NIC, VM, and private IP correlation (ARG-enriched)
        - Support for both NIC-based and IP-based backend configurations

    • Orphaned Resources
        - Managed Disks
            - Unattached disks identified via ARG (state, ownership, and age thresholds)
        - Network Interfaces
            - NICs without VM, Private Endpoint, or managed association
            - Includes resolved private/public IP and subnet context

      
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
        - Comprehensive VM inventory including compute, storage, networking, tagging, and agent health

    • NSG_Custom_<timestamp>.csv
        - NSG rules (one rule per row) with NIC, VM, IP, and subnet associations

    • vNet_<timestamp>.csv
        - Virtual network and subnet configuration with NSG and route table references

    • PIP_<timestamp>.csv
        - Public IP inventory with allocation method, SKU, FQDN, and association details

    • LBe_<timestamp>.csv
        - Load Balancer inventory including frontend IPs, backend pools, and backend NIC, VM, and private IP correlation

    • Orphan_Disk_<timestamp>.csv
        - Unattached managed disks identified via ARG-based ownership and state analysis

    • Orphan_NIC_<timestamp>.csv
        - Network interfaces without VM, Private Endpoint, or managed association, including IP and subnet context

.PARAMETER * Tenant ID and type are prompted interactively
    -NoARM switch enables ARG-only inventory mode (no ARM augmentation)

.INTERACTIVE PROMPTS
    • Tenant ID
    • Tenant type (Commercial or Azure Government)
    • Repeat execution for additional tenants (Y/N)

.NOTES
    AUTHOR:   Mark Lehrmann
    VERSION:  v7.6.0 (2026-06-24)

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
    [x] Replace remaining ARM networking calls with ARG where possible
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

# Get absolute start time
$ScriptStartTime = Get-Date

Write-Host (
    "Script started: {0}" -f
    $ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss')
) -ForegroundColor DarkGray

# Load the query definitions from the external file
$queryFile = Join-Path $PSScriptRoot 'Ex-Az_Inventory_multitenant.queries.ps1'

if (-not (Test-Path $queryFile)) {
    throw "Query definition file not found: $queryFile"
}

. $queryFile

$requiredQueries = @(
    'VM_BASE_QUERY',
    'NIC_QUERY',
    'DISK_QUERY',
    'VNET_QUERY',
    'PIP_QUERY',
    'NSG_QUERY'
)

foreach ($query in $requiredQueries) {

    $var = Get-Variable -Name $query -Scope Global -ErrorAction SilentlyContinue

    if (-not $var) {
        throw "Required query '$query' was not defined by $queryFile"
    }

    if ([string]::IsNullOrWhiteSpace([string]$var.Value)) {
        throw "Required query '$query' is defined but empty in $queryFile"
    }
}

Write-Host (
    "Loaded {0} query definitions from {1}" -f
    $requiredQueries.Count,
    (Split-Path $queryFile -Leaf)
) -ForegroundColor DarkGreen

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
if ($NoARM.IsPresent) {

    $InventoryMode = 'NoARM / ARG-only (⚠️ Incomplete data possible)'

    Write-Host ("Inventory mode: {0}" -f $InventoryMode) -ForegroundColor Yellow

    Write-Host "⚠️  ARG-only mode: VM power state, PIPs, and some resources may be missing or reported as Unknown." -ForegroundColor DarkYellow

}
else {

    $InventoryMode = 'Full inventory mode / ARG + targeted ARM augmentation'

    Write-Host ("Inventory mode: {0}" -f $InventoryMode) -ForegroundColor Cyan

}

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

    <#
#region Queries
#################################
See Ex-Az_Inventory_multitenant.queries.ps1 for the ARG query definitions used in this script.
#################################
#endregion Queries
#>

    #region Tenant Init and Start
    #################################
        
    try {
        # --- ARG VM discovery ---
        Write-Host "ARG: Running VM query..." -ForegroundColor Cyan
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
        Write-Host "ARG: Running NIC query..." -ForegroundColor Cyan
        $nicRowsArg = Get-AllAzGraph -Query $NIC_QUERY -SubscriptionId $subIds -BatchSize 1000

        Write-Host "ARG: Running Disk query..." -ForegroundColor Cyan
        $diskRowsArg = Get-AllAzGraph -Query $DISK_QUERY -SubscriptionId $subIds -BatchSize 1000
            
        Write-Host "ARG: Running NSG query..." -ForegroundColor Cyan
        $nsgRowsArg = Get-AllAzGraph -Query $NSG_QUERY -SubscriptionId $subIds -BatchSize 1000

        Write-Host "ARG: Running vNet query..." -ForegroundColor Cyan
        $vNetRows = Get-AllAzGraph -Query $VNET_QUERY -SubscriptionId $subIds -BatchSize 1000

        Write-Host "ARG: Running Public IP query..." -ForegroundColor Cyan
        $pipRows = Get-AllAzGraph -Query $PIP_QUERY -SubscriptionId $subIds -BatchSize 1000

            
        $pipArgById = @{}
        foreach ($p in @($pipRows)) {
            if ($p.id) { $pipArgById[[string]$p.id] = $p }
        }

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
                #################################
                #endregion Subscription Loop

                #region Virtual Machine Details (ARG-first)
                #################################

                Update-SubProgress -Phase "Building VM inventory objects" -SubPercent 85

                $virtual_machine_object = [System.Collections.Generic.List[object]]::new()

                foreach ($vm in $vmRowsSub) {

                    
                    # VM status / agent / extension state
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
                    
                    # VM size / SKU enrichment
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
                    
                    # Placement metadata
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

                    
                    # NIC / IP / subnet resolution
                    $ifName = ''
                    $vNet = ''
                    $subnet = ''
                    $privateIp = ''
                    $privateIpAlloc = ''

                    # ARG NIC/IP/subnet resolution.
                    # Works in both NoARM and Full modes because $nicIndexById is built from $NIC_QUERY.
                    $vm_ip_details = [System.Collections.Generic.List[object]]::new()

                    foreach ($nicRef in @($vm.nicRefs)) {
                        $nicId = [string]$nicRef.id

                        if ([string]::IsNullOrWhiteSpace($nicId)) {
                            continue
                        }

                        if (-not $nicIndexById.ContainsKey($nicId)) {
                            continue
                        }

                        $nic = $nicIndexById[$nicId]

                        foreach ($ipConfig in @($nic.ipConfigs)) {
                            if (-not $ipConfig -or -not $ipConfig.properties) {
                                continue
                            }

                            $subnetId = $null

                            if ($ipConfig.properties.subnet -and $ipConfig.properties.subnet.id) {
                                $subnetId = [string]$ipConfig.properties.subnet.id
                            }

                            $vnetName = $null
                            $subnetName = $null

                            if (-not [string]::IsNullOrWhiteSpace($subnetId)) {
                                $vnetName = Get-IdSegment -Id $subnetId -SegmentName 'virtualNetworks'
                                $subnetName = Get-IdSegment -Id $subnetId -SegmentName 'subnets'
                            }

                            $vm_ip_details.Add([pscustomobject]@{
                                    ifName     = [string]$nic.name
                                    PrivateIP  = [string]$ipConfig.properties.privateIPAddress
                                    Allocation = [string]$ipConfig.properties.privateIPAllocationMethod
                                    VNet       = $vnetName
                                    Subnet     = $subnetName
                                    Primary    = $ipConfig.properties.primary
                                })
                        }
                    }

                    $ifName = (($vm_ip_details.ifName | Where-Object { $_ } | Select-Object -Unique) -join ';')
                    $vNet = (($vm_ip_details.VNet | Where-Object { $_ } | Select-Object -Unique) -join ';')
                    $subnet = (($vm_ip_details.Subnet | Where-Object { $_ } | Select-Object -Unique) -join ';')
                    $privateIp = (($vm_ip_details.PrivateIP | Where-Object { $_ } | Select-Object -Unique) -join ';')
                    $privateIpAlloc = (($vm_ip_details.Allocation | Where-Object { $_ } | Select-Object -Unique) -join ';')

                    # Disk resolution
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

                        if ($null -ne $vm.osDiskSizeGB -and [string]$vm.osDiskSizeGB -ne '') {
                            try {
                                $os_disk_size_gb = [int]$vm.osDiskSizeGB
                            }
                            catch {
                                $os_disk_size_gb = 0
                            }
                        }

                        if ($null -ne $vm.TotalManagedDiskSizeGB_ARG -and [string]$vm.TotalManagedDiskSizeGB_ARG -ne '') {
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

                    # OS creation / OS guest details
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

                    # Final VM object
                    $vmObject = [ordered]@{
                        TenantDomain            = $TenantDomain
                        SubscriptionName        = $subscription_name
                        ResourceGroupName       = $vm.resourceGroup
                        Location                = $location
                        VMName                  = $vm.name
                        VMStatus                = $powerState
                        VMSize                  = $vmSize
                        SKUvcpu                 = $vcpuBase
                        vCPUs                   = $vcpuAvail
                        MemoryGB                = $memory
                        Zone                    = $vm_zone
                        Set                     = $vm_set
                        VM_Agent_Status         = $vmAgentStatus
                        AzureMonitorAgent       = $amaStatus
                        MDEAgent                = $mdeStatus
                        ifName                  = $ifName
                        vNet                    = $vNet
                        Subnet                  = $subnet
                        PrivateIP               = $privateIp
                        PrivateIPalloc          = $privateIpAlloc
                        LicenseType             = $vm.licenseType
                        OSName                  = $osName
                        OSVersion               = $osVersion
                        OSType                  = $vm.osType
                        
                        OSImagePub              = if ($vm.imagePub) { $vm.imagePub } else { 'N/A' }
                        OSImageOffer            = if ($vm.imageOffer) { $vm.imageOffer } else { 'N/A' }
                        OSImageSku              = if ($vm.imageSku) { $vm.imageSku } else { 'N/A' }
                        OSImageVersion          = if ($vm.imageVersion) { $vm.imageVersion } else { 'N/A' }

                        OSImageId               = if ($vm.imageId) { $vm.imageId } else { 'N/A' }
                        OSImageExactVersion     = if ($vm.imageExactVersion) { $vm.imageExactVersion } else { 'N/A' }
                        SharedGalleryImageId    = if ($vm.sharedGalleryImageId) { $vm.sharedGalleryImageId } else { 'N/A' }
                        CommunityGalleryImageId = if ($vm.communityGalleryImageId) { $vm.communityGalleryImageId } else { 'N/A' }

                        OSDate                  = $osCreation
                        AdminUserName           = $vm.adminUser
                        OSDiskAccessId          = $OSdiskAccessId
                        ManagedOSDiskURI        = $os_disk_details_managed
                        ManagedOSDiskSizeGB     = $os_disk_size_gb
                        TotalManagedDiskSizeGB  = $total_disk_size_gb
                        UnManagedOSDiskURI      = $os_disk_details_unmanaged
                        DataDiskNames           = ($dataDiskNames -join ';')
                    }


                    # Raw tag preservation for global tag header normalization
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
            }
            #################################
            #endregion Virtual Machine Details (ARG-first)


            #region Network Security Groups Details (ARG-native)
            #################################
            $Azure_NSG_output = foreach ($nsg in $nsgRowsArg | Where-Object { $_.subscriptionId -eq $subscription_id }) {

                $resolvedNICs = @()
                $resolvedVMs = @()
                $resolvedIPs = @()
                $resolvedPIPs = @()

                foreach ($nicRef in @($nsg.networkInterfaces)) {
                    $nicId = [string]$nicRef.id

                    if ([string]::IsNullOrWhiteSpace($nicId)) { continue }
                    if (-not $nicIndexById.ContainsKey($nicId)) { continue }

                    $nic = $nicIndexById[$nicId]
                    $resolvedNICs += $nic.name

                    foreach ($ipConf in @($nic.ipConfigs)) {

                        if ($ipConf.properties.privateIPAddress) {
                            $resolvedIPs += [string]$ipConf.properties.privateIPAddress
                        }

                        if ($nic.virtualMachineId -and $vmNameById.ContainsKey($nic.virtualMachineId)) {
                            $resolvedVMs += $vmNameById[$nic.virtualMachineId]
                        }

                        if ($ipConf.properties.publicIPAddress -and $ipConf.properties.publicIPAddress.id) {
                            $pipId = [string]$ipConf.properties.publicIPAddress.id

                            if ($pipArgById.ContainsKey($pipId)) {
                                $resolvedPIPs += $pipArgById[$pipId].PublicIpAddress
                            }
                        }
                    }
                }

                $subnetNames = foreach ($s in @($nsg.subnets)) {
                    if ($s.id) { Get-IdSegment -Id $s.id -SegmentName 'subnets' }
                }

                [pscustomobject]@{
                    TenantDomain             = $TenantDomain
                    Subscription             = $subscription_name
                    Resourc_Group            = $nsg.resourceGroup
                    Location                 = $nsg.location
                    NSG_Name                 = $nsg.NSG_Name
                    Rule_Name                = $nsg.Rule_Name
                    Priority                 = $nsg.Priority
                    Protocol                 = $nsg.Protocol
                    Direction                = $nsg.Direction
                    SourcePortRange          = $nsg.SourcePortRange
                    DestinationPortRange     = $nsg.DestinationPortRange
                    SourceAddressPrefix      = $nsg.SourceAddressPrefix
                    DestinationAddressPrefix = $nsg.DestinationAddressPrefix
                    Access                   = $nsg.Access

                    'NSG VMs'                = (($resolvedVMs | Select-Object -Unique) -join ';')
                    'NSG NICs'               = (($resolvedNICs | Select-Object -Unique) -join ';')
                    'NSG NIC IP'             = (($resolvedIPs  | Select-Object -Unique) -join ';')
                    'NSG NIC PIP'            = (($resolvedPIPs | Select-Object -Unique) -join ';')

                    'NSG Subnets'            = (($subnetNames | Select-Object -Unique) -join ';')
                    Description              = $nsg.Description
                }
            }

            Add-RangeSafe -Target $AzNSG_Inventory -Items $Azure_NSG_output

            #endregion Network Security Groups Details (ARG-native)


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

            # Index Public IPs by resource ID for quick resolution (ARG-based)
            $pipById = $pipArgById

            foreach ($lb in @($AzureLBList)) {

                $feNames = @($lb.FrontendIpConfigurations | ForEach-Object { $_.Name } | Where-Object { $_ })
                $beNames = @($lb.BackendAddressPools      | ForEach-Object { $_.Name } | Where-Object { $_ })

                # Collect all frontend IPs (private and/or public)
                $frontendIps = [System.Collections.Generic.List[string]]::new()

                foreach ($fe in @($lb.FrontendIpConfigurations)) {
                    if (-not $fe) { continue }

                    # Private IP
                    if ($fe.PrivateIpAddress) {
                        $frontendIps.Add([string]$fe.PrivateIpAddress)
                    }

                    # Public IP via ARG
                    if ($fe.PublicIpAddress -and $fe.PublicIpAddress.Id) {

                        $pubid = [string]$fe.PublicIpAddress.Id

                        $pip = $null
                        if ($pipById.ContainsKey($pubid)) {
                            $pip = $pipById[$pubid]
                        }

                        if ($pip -and -not [string]::IsNullOrWhiteSpace($pip.PublicIpAddress)) {
                            $frontendIps.Add([string]$pip.PublicIpAddress)
                        }
                        else {
                            # Fallback if ARG hasn't populated IP yet
                            $frontendIps.Add("PIP:$(( $pubid -split '/' )[-1])")
                        }
                    }
                }

                $frontendIpText = ($frontendIps | Where-Object { $_ } | Select-Object -Unique) -join ';'

                # Backend correlation
                $backendNICs = @()
                $backendVMs = @()
                $backendIPs = @()

                foreach ($pool in @($lb.BackendAddressPools)) {

                    # --- NIC-based backend resolution ---
                    foreach ($ipRef in @($pool.BackendIpConfigurations)) {

                        $ipId = [string]$ipRef.Id
                        if (-not $ipId) { continue }

                        $nicId = $ipId -replace '/ipConfigurations/.+$', ''
                        if (-not $nicIndexById.ContainsKey($nicId)) { continue }

                        $nic = $nicIndexById[$nicId]

                        # NIC name
                        $backendNICs += $nic.name

                        # VM resolution
                        if ($nic.virtualMachineId -and $vmNameById.ContainsKey($nic.virtualMachineId)) {
                            $backendVMs += $vmNameById[$nic.virtualMachineId]
                        }

                        # Private IP
                        foreach ($ipconf in @($nic.ipConfigs)) {
                            if ($ipconf.properties.privateIPAddress) {
                                $backendIPs += [string]$ipconf.properties.privateIPAddress
                            }
                        }
                    }

                    # --- IP-based backend fallback ---
                    foreach ($addr in @($pool.LoadBalancerBackendAddresses)) {

                        if ($addr.IpAddress) {
                            $backendIPs += [string]$addr.IpAddress
                        }

                        if ($addr.Name) {
                            $backendNICs += "IPBackend:$($addr.Name)"
                        }
                    }
                }

                # Final object
                $azure_load_balancer_object.Add([pscustomobject]@{
                        Tenant                       = $TenantDomain
                        Subscription                 = $subscription_name
                        ResourceGroupName            = $lb.ResourceGroupName
                        Name                         = $lb.Name
                        PrivateIP                    = $frontendIpText
                        Location                     = $lb.Location
                        FrontendIpConfigurationsName = (($feNames | Select-Object -Unique) -join ';')
                        BackendAddressPoolsName      = (($beNames | Select-Object -Unique) -join ';')

                        # ✅ New fields
                        BackendNICs                  = (($backendNICs | Select-Object -Unique) -join ';')
                        BackendVMs                   = (($backendVMs  | Select-Object -Unique) -join ';')
                        BackendPrivateIPs            = (($backendIPs  | Select-Object -Unique) -join ';')
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

Write-Host "VM count: $($AzVM_Inventory.Count)"
Write-Host "vNet count: $($AzvNet_Inventory.Count)"
Write-Host "PIP count: $($AzPIP_Inventory.Count)"

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

    # Add suffix for partial (NoARM) mode
    $runModeSuffix = if ($NoARM.IsPresent) { "-partial" } else { "" }

    Set-Location $script:RunOutputFolder

    if ($AzVM_Inventory_multi_export.Count -gt 0) {
        $AzVM_Inventory_multi_export | Export-Csv (('{0}{1}{2}.csv' -f $CSV_VM_name, $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzNSG_Inventory_multi.Count -gt 0) {
        $AzNSG_Inventory_multi | Export-Csv (("NSG_Custom_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzvNet_Inventory_multi.Count -gt 0) {
        $AzvNet_Inventory_multi | Export-Csv (("vNet_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzPIP_Inventory_multi.Count -gt 0) {
        $AzPIP_Inventory_multi | Export-Csv (("PIP_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzLBe_Inventory_multi.Count -gt 0) {
        $AzLBe_Inventory_multi | Export-Csv (("LBe_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzOrphanDisk_Inventory_multi.Count -gt 0) {
        $AzOrphanDisk_Inventory_multi | Export-Csv (("Orphan_Disk_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }
    if ($AzOrphanNIC_Inventory_multi.Count -gt 0) {
        $AzOrphanNIC_Inventory_multi | Export-Csv (("Orphan_NIC_{0}{1}.csv" -f $runStampText, $runModeSuffix)) -NoTypeInformation -Force
    }

    $ScriptEndTime = Get-Date
    $ActualRuntime = $ScriptEndTime - $ScriptStartTime

    Write-Host ""
    Write-Host (
        "Script started : {0}" -f
        $ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss')
    ) -ForegroundColor DarkGray

    Write-Host (
        "Script ended   : {0}" -f
        $ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss')
    ) -ForegroundColor DarkGray

    Write-Host (
        "Actual runtime : {0}" -f
        $ActualRuntime.ToString('hh\:mm\:ss')
    ) -ForegroundColor Magenta

    Write-Host ("Inventory exported to: {0}" -f $script:RunOutputFolder) -ForegroundColor Green
}
finally {
    Set-Location $originalLocation
}
#################################
#endregion Build and Export
