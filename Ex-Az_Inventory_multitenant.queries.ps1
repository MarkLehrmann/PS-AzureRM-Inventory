#region Queries
#################################
$Global:VM_BASE_QUERY = @'
Resources
| where type =~ "microsoft.compute/virtualmachines"
| extend
    vmSize              = tostring(properties.hardwareProfile.vmSize),
    timeCreated         = todatetime(properties.timeCreated),
    availSetId          = tostring(properties.availabilitySet.id),
    osType              = tostring(properties.storageProfile.osDisk.osType),
    osDiskManagedId     = tostring(properties.storageProfile.osDisk.managedDisk.id),
    osDiskName          = tostring(properties.storageProfile.osDisk.name),
    osDiskVhdUri        = tostring(properties.storageProfile.osDisk.vhd.uri),
    osDiskSizeGB_Base   = tolong(properties.storageProfile.osDisk.diskSizeGB),
    dataDisksRaw        = properties.storageProfile.dataDisks,
    imagePub            = tostring(properties.storageProfile.imageReference.publisher),
    imageOffer          = tostring(properties.storageProfile.imageReference.offer),
    imageSku            = tostring(properties.storageProfile.imageReference.sku),
    imageVersion        = tostring(properties.storageProfile.imageReference.version),
    imageId             = tostring(properties.storageProfile.imageReference.id),
    imageExactVersion   = tostring(properties.storageProfile.imageReference.exactVersion),
    sharedGalleryImageId = tostring(properties.storageProfile.imageReference.sharedGalleryImageId),
    communityGalleryImageId = tostring(properties.storageProfile.imageReference.communityGalleryImageId),
    adminUser           = tostring(properties.osProfile.adminUsername),
    computerName        = tostring(properties.osProfile.computerName),
    nicRefs             = properties.networkProfile.networkInterfaces,
    licenseType         = iif(isempty(tostring(properties.licenseType)), "NA", tostring(properties.licenseType)),
    argPowerState       = tostring(properties.extended.instanceView.powerState.displayStatus),
    argPowerStateCode   = tostring(properties.extended.instanceView.powerState.code),
    argOSName           = tostring(properties.extended.instanceView.osName),
    argOSVersion        = tostring(properties.extended.instanceView.osVersion),
    argHyperVGeneration = tostring(properties.extended.instanceView.hyperVGeneration)
| mv-expand dataDisk = iif(isnull(dataDisksRaw) or array_length(dataDisksRaw) == 0, dynamic([{}]), dataDisksRaw) to typeof(dynamic)
| extend
    dataDiskName        = tostring(dataDisk.name),
    dataDiskSizeGB      = tolong(dataDisk.diskSizeGB)
| summarize
    subscriptionId       = take_any(subscriptionId),
    resourceGroup        = take_any(resourceGroup),
    name                 = take_any(name),
    location             = take_any(location),
    zones                = take_any(zones),
    tags                 = take_any(tags),
    licenseType          = take_any(licenseType),
    vmSize               = take_any(vmSize),
    timeCreated          = take_any(timeCreated),
    availSetId           = take_any(availSetId),
    osType               = take_any(osType),
    osDiskManagedId      = take_any(osDiskManagedId),
    osDiskName           = take_any(osDiskName),
    osDiskVhdUri         = take_any(osDiskVhdUri),
    osDiskSizeGB         = take_any(osDiskSizeGB_Base),
    dataDisks            = take_any(dataDisksRaw),
    imagePub             = take_any(imagePub),
    imageOffer           = take_any(imageOffer),
    imageSku             = take_any(imageSku),
    imageVersion         = take_any(imageVersion),
    imageId              = take_any(imageId),
    imageExactVersion    = take_any(imageExactVersion),
    sharedGalleryImageId = take_any(sharedGalleryImageId),
    communityGalleryImageId= take_any(communityGalleryImageId),
    adminUser            = take_any(adminUser),
    computerName         = take_any(computerName),
    nicRefs              = take_any(nicRefs),
    argPowerState        = take_any(argPowerState),
    argPowerStateCode    = take_any(argPowerStateCode),
    argOSName            = take_any(argOSName),
    argOSVersion         = take_any(argOSVersion),
    argHyperVGeneration  = take_any(argHyperVGeneration),
    DataDiskNames_SET    = make_set_if(dataDiskName, isnotempty(dataDiskName), 500),
    DataDiskSizeGB_ARG   = sum(coalesce(dataDiskSizeGB, 0))
  by id
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
    AzureMonitorAgent_ARG = "ARG:NotEvaluated",
    MDEAgent_ARG          = "ARG:NotEvaluated",

    ifName_ARG             = "",
    vNet_ARG               = "",
    Subnet_ARG             = "",
    PrivateIP_ARG          = "",
    PrivateIPalloc_ARG     = "",

    osDiskAccessId         = "",
    osDiskTimeCreated      = timeCreated,
    osDiskState            = "",
    osDiskSkuName          = "",

    DataDiskNames_ARG      = strcat_array(DataDiskNames_SET, ";"),
    TotalManagedDiskSizeGB_ARG = tolong(coalesce(osDiskSizeGB, 0)) + tolong(coalesce(DataDiskSizeGB_ARG, 0)),

    ExtensionNames_ARG               = "",
    ExtensionTypes_ARG               = "",
    ExtensionProvisioningStates_ARG  = "",
    AMA_ExtensionNames_ARG           = dynamic([]),
    AMA_ProvisioningStates_ARG       = dynamic([]),
    MDE_ExtensionNames_ARG           = dynamic([]),
    MDE_ProvisioningStates_ARG       = dynamic([])
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
    imageId,
    imageExactVersion,
    sharedGalleryImageId,
    communityGalleryImageId,
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

    ifName_ARG,
    vNet_ARG,
    Subnet_ARG,
    PrivateIP_ARG,
    PrivateIPalloc_ARG,

    osDiskSizeGB,
    osDiskAccessId,
    osDiskTimeCreated,
    osDiskState,
    osDiskSkuName,
    DataDiskNames_ARG,
    DataDiskSizeGB_ARG,
    TotalManagedDiskSizeGB_ARG,

    ExtensionNames_ARG,
    ExtensionTypes_ARG,
    ExtensionProvisioningStates_ARG,
    AMA_ExtensionNames_ARG,
    AMA_ProvisioningStates_ARG,
    MDE_ExtensionNames_ARG,
    MDE_ProvisioningStates_ARG
'@

$Global:NIC_QUERY = @'
Resources
| where type =~ "microsoft.network/networkinterfaces"
| extend
    ipConfigs         = properties.ipConfigurations,
    virtualMachineId  = tostring(properties.virtualMachine.id),
    privateEndpointId = tostring(properties.privateEndpoint.id),
    managedById       = tostring(managedBy)
| project
    id,
    subscriptionId,
    resourceGroup,
    name,
    location,
    ipConfigs,
    virtualMachineId,
    privateEndpointId,
    managedById
'@

$Global:DISK_QUERY = @'
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
    lastOwnershipUpdate = coalesce(
                              todatetime(properties.LastOwnershipUpdateTime),
                              todatetime(properties.lastOwnershipUpdateTime)
                          )
| project
    id,
    subscriptionId,
    resourceGroup,
    name,
    location,
    diskSizeGB,
    diskAccessId,
    timeCreated,
    diskState,
    managedById,
    skuName,
    osType,
    lastOwnershipUpdate
'@

$Global:VNET_QUERY = @'
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
    Subnet_Name    = tostring(subnet.name),
    Subnet_Address,
    Subnet_NSG_Id  = tostring(subnet.properties.networkSecurityGroup.id),
    Route_Table_Id = tostring(subnet.properties.routeTable.id),
    vNet_Peers     = array_length(properties.virtualNetworkPeerings)
'@

$Global:PIP_QUERY = @'
Resources
| where type =~ "microsoft.network/publicipaddresses"
| project
    id,
    subscriptionId,
    resourceGroup,
    name,
    location,
    PublicIpAddress  = tostring(properties.ipAddress),
    AllocationMethod = tostring(properties.publicIPAllocationMethod),
    SkuName          = tostring(sku.name),
    SkuTier          = tostring(sku.tier),
    Fqdn             = coalesce(tostring(properties.dnsSettings.fqdn), ""),
    IpConfigId       = tostring(properties.ipConfiguration.id),
    NatGatewayId     = tostring(properties.natGateway.id)
'@

$Global:NSG_QUERY = @'
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| extend
    securityRules = properties.securityRules,
    subnets       = properties.subnets,
    networkInterfaces = properties.networkInterfaces
| mv-expand rule = securityRules
| project
    id,
    subscriptionId,
    resourceGroup,
    NSG_Name = name,
    location,
    subnets,
    networkInterfaces,

    Rule_Name = tostring(rule.name),
    Priority  = toint(rule.properties.priority),
    Protocol  = tostring(rule.properties.protocol),
    Direction = tostring(rule.properties.direction),
    Access    = tostring(rule.properties.access),
    SourcePortRange      = tostring(rule.properties.sourcePortRange),
    DestinationPortRange = tostring(rule.properties.destinationPortRange),
    SourceAddressPrefix  = tostring(rule.properties.sourceAddressPrefix),
    DestinationAddressPrefix = tostring(rule.properties.destinationAddressPrefix),
    Description = tostring(rule.properties.description)
'@