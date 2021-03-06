﻿<#
#          Script: Azure Inventory Script                                           
#            Date: August 13, 2018                                                                     
#          Author: Manjunath
#

DESCRIPTION:
This script will pull the infrastructure details of the Azure subscriptions. Details will be stored under the folder "c:\AzureInventory"
If you have multiple subscriptions, a separate folder will be created for individual subscription.
CSV files will be created for individual services (Virtual Machines, NSG rules, Storage Account, Virtual Networks, Azure Load Balancers) inside the subscription's directory

add TenantID to command line to restrict scope to a single tenant.  -mtl

#>

param(
    [string]$tenantId=""
) 


function Invoke-GetAzureInventoryFunction{
    
    # Sign into Azure Portal
    login-azurermaccount -tenantid $tenantId 

    # Fetching subscription list
    $subscription_list = Get-AzureRmSubscription -TenantId $tenantId 

    # Fetch current working directory 
    $working_directory = "c:\AzureInventory"

    new-item $working_directory -ItemType Directory -Force

    
    # Fetching the IaaS inventory list for each subscription
    
    
    foreach($subscription_list_iterator in $subscription_list){
        $subscription_id = $subscription_list_iterator.id
        $subscription_name = $subscription_list_iterator.name

        if($subscription_list_iterator.State -ne "Disabled"){
            Get-AzureInventory($subscription_id)
        }
        
    }

    

    <#
    Get-AzureRmSubscription | 
    ForEach-Object{
        #Select-AzureRmSubscription -SubscriptionId $_.ID
        if($_.State -ne "Disabled"){
            write-output "Generating inventory for the subscription: " $_.TenantId
            Get-AzureInventory($_.TenantId, $_.Name)
        }
        
    }

    #>
}



function Get-AzureInventory{

Param(
[String]$subscription_id
)

# Selecting the subscription
Select-AzureRmSubscription -Subscription $subscription_id



# Create a new directory with the subscription name
$path_to_store_inventory_csv_files = "c:\AzureInventory\" + $subscription_id

# Fetch the Resources from the subscription
$resources = Get-AzureRmResource

# Fetch the Virtual Machines from the subscription
$azureVMDetails = get-azurermvm

# Fetch the NIC details from the subscription
$azureNICDetails = Get-AzureRmNetworkInterface

# Fetch the PublicIP details from the subscription
$azurePublicIPs = Get-AzureRmPublicIpAddress

# Fetch the Virtual Networks from the subscription
$azureVirtualNetworkDetails = Get-AzureRmVirtualNetwork

# Fetch the NSG rules from the subscription
$azureNSGDetails = Get-AzureRmNetworkSecurityGroup

# Fetch the Azure load balancer details
$AzureLBList = Get-AzureRmLoadBalancer

# Create a new directory with the subscription name
new-item $path_to_store_inventory_csv_files -ItemType Directory -Force

# Change the directory location to store the CSV files
Set-Location -Path $path_to_store_inventory_csv_files



#####################################################################
#    Fetching Virtual Machine Details                               #
#####################################################################

    $virtual_machine_object = $null
    $virtual_machine_object = @()


    # Iterating over the Virtual Machines under the subscription
        
        foreach($azureVMDetails_Iterator in $azureVMDetails){
        
        # Fetching the satus
        $vm_status = get-azurermvm -ResourceGroupName $azureVMDetails_Iterator.resourcegroupname -name $azureVMDetails_Iterator.name -Status

        #Fetching the private IP
        foreach($azureNICDetails_iterator in $azureNICDetails){
            if($azureNICDetails_iterator.Id -eq $azureVMDetails_Iterator.NetworkProfile.NetworkInterfaces.id) {
            #write-Host $vm.NetworkInterfaceIDs
            $private_ip_address = $azureNICDetails_iterator.IpConfigurations.privateipaddress
			$private_ip_allocation = $azureNICDetails_iterator.IpConfigurations.PrivateIpAllocationMethod
            }
        }

        #Fetching data disk names
        $data_disks = $azureVMDetails_Iterator.StorageProfile.DataDisks
        $data_disk_name_list = ''
        <#
        if($data_disks.Count -eq 0){
            $data_disk_name_list = "No Data Disk Attached"
            #write-host $data_disk_name_list
        }elseif($data_disks.Count -ge 1) {

        #>
            foreach ($data_disks_iterator in $data_disks) {
            $data_disk_name_list_temp = $data_disk_name_list + "; " +$data_disks_iterator.name 
            #Trimming the first three characters which contain --> " ; "
            $data_disk_name_list = $data_disk_name_list_temp.Substring(2)
            #write-host $data_disk_name_list
            }

        #}

            

            # Fetching OS Details (Managed / un-managed)

            if($azureVMDetails_Iterator.StorageProfile.OsDisk.manageddisk -eq $null){
                # This is un-managed disk. It has VHD property

                $os_disk_details_unmanaged = $azureVMDetails_Iterator.StorageProfile.OsDisk.Vhd.Uri
                $os_disk_details_managed = "This VM has un-managed OS Disk"

            }else{
                
                $os_disk_details_managed = $azureVMDetails_Iterator.StorageProfile.OsDisk.ManagedDisk.Id
                $os_disk_details_unmanaged = "This VM has Managed OS Disk"
            }

            $virtual_machine_object_temp = new-object PSObject 
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "ResourceGroupName" -Value $azureVMDetails_Iterator.ResourceGroupName
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "VMName" -Value $azureVMDetails_Iterator.Name
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "VMStatus" -Value $vm_status.Statuses[1].DisplayStatus
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "Location" -Value $azureVMDetails_Iterator.Location
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "VMSize" -Value $azureVMDetails_Iterator.HardwareProfile.VmSize
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "OSDisk" -Value $azureVMDetails_Iterator.StorageProfile.OsDisk.OsType
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "OSImageType" -Value $azureVMDetails_Iterator.StorageProfile.ImageReference.sku
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "AdminUserName" -Value $azureVMDetails_Iterator.OSProfile.AdminUsername
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "NICId" -Value $azureVMDetails_Iterator.NetworkProfile.NetworkInterfaces.id
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "OSVersion" -Value $azureVMDetails_Iterator.StorageProfile.ImageReference.Sku
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "PrivateIP" -Value $private_ip_address
			$virtual_machine_object_temp | add-member -membertype NoteProperty -name "PrivateIPalloc" -Value $private_ip_allocation
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "ManagedOSDiskURI" -Value $os_disk_details_managed
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "UnManagedOSDiskURI" -Value $os_disk_details_unmanaged
            $virtual_machine_object_temp | add-member -membertype NoteProperty -name "DataDiskNames" -Value $data_disk_name_list


            $virtual_machine_object += $virtual_machine_object_temp

            
        }

        $virtual_machine_object | Export-Csv "Virtual_Machine_details.csv" -NoTypeInformation -Force



############################################################################
#    Fetching custom Network Security Groups Details                       #
############################################################################

            $network_security_groups_object = $null
            $network_security_groups_object = @()

            foreach($azureNSGDetails_Iterator in $azureNSGDetails){
        
        

            $securityRulesPerNSG = $azureNSGDetails_Iterator.SecurityRules
            if($securityRulesPerNSG -eq $null){
                continue
            }

            foreach($securityRulesPerNSG_Iterator in $securityRulesPerNSG) {

                $network_security_groups_object_temp = new-object PSObject
				
				$network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "NSG Name" -Value $azureNSGDetails_Iterator.Name
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "Rule Name" -Value $securityRulesPerNSG_Iterator.Name
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "Priority" -Value $securityRulesPerNSG_Iterator.Priority
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "Protocol" -Value $securityRulesPerNSG_Iterator.Protocol
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "Direction" -Value $securityRulesPerNSG_Iterator.Direction
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "SourcePortRange" -Value ($securityRulesPerNSG_Iterator | Select-Object @{Name=“SourcePortRange”;Expression={$_.SourcePortRange}})
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "DestinationPortRange" -Value ($securityRulesPerNSG_Iterator | Select-Object @{Name=“DestinationPortRange”;Expression={$_.DestinationPortRange}})
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "SourceAddressPrefix" -Value ($securityRulesPerNSG_Iterator | Select-Object @{Name=“SourceAddressPrefix”;Expression={$_.SourceAddressPrefix}})
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "DestinationAddressPrefix" -Value ($securityRulesPerNSG_Iterator | Select-Object @{Name=“DestinationAddressPrefix”;Expression={$_.DestinationAddressPrefix}})
                $network_security_groups_object_temp | add-member -MemberType NoteProperty -Name "Access" -Value $securityRulesPerNSG_Iterator.Access
                
                $network_security_groups_object += $network_security_groups_object_temp
            }
        
            # Setting the pointer to the next row and first column
            
            
        }

        if($network_security_groups_object -ne $null){
                $network_security_groups_object | Export-Csv "nsg_custom_rules_details.csv" -NoTypeInformation -Force
        }
        


#####################################################################
#    Fetching Virtual Network Details                               #
#####################################################################

            $Output_vNets = $null
            $Output_vNets = @()
					
			$vNets_All = Get-AzureRmVirtualNetwork
            $Output_vNets = foreach($vNet in $vNets_All)
			{
				$vNet_Subnet_Properties = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vNet
				
				foreach($Subnet in $vNet_Subnet_Properties){
				
					[pscustomobject]@{
												
							Resourc_Group = $vNet.ResourceGroupName 
							Location = $vNet.Location
							Virtual_Net = $vNet.Name
							vNet_Addresses = ($vNet.AddressSpace.AddressPrefixes -join "`n" )
							vNet_DNS = $vNet.DhcpOptions.DnsServers -join "`n" 
							Subnet_Name = $Subnet.Name
							Subnet_Address = $Subnet.AddressPrefix -join "`n" 
							
					}
				}
			}	
			
        $Output_vNets | Export-Csv "Virtual_networks_details.csv" -NoTypeInformation -Force



#####################################################################
#    Fetching Public IP Details                                     #
#####################################################################		
		
    $Output_PIP = foreach($azurePublicIP in $azurePublicIPs){
 
	$azureNIC = $azureNICDetails.Where({$_.IpConfigurations.publicipaddress.id -eq $azurePublicIP.Id})
	$azureVM = $azureVMDetails.Where({$_.Id -eq $azureNIC.VirtualMachine.Id})
	
		[pscustomobject]@{
        
		Name = $azurePublicIP.Name
		PublicIpAddress = $azurePublicIP.IpAddress
		FQDN = ($azurePublicIP.DnsSettingsText | ConvertFrom-Json).fqdn
		SKU = ($azurePublicIP.SkuText | ConvertFrom-Json).Name
		AllocationMethod = $azurePublicIP.PublicIpAllocationMethod
		Location = $azureVM.Location
		ResourceGroupName = $azurePublicIP.ResourceGroupName
		VirtualMachineName = $azureVM.Name
		NetworkInterface = $azureNIC.Name
		IpConfiguration = $azurePublicIP.IpConfiguration.Id.Split("/")[-1]
		InternalIpAddress = ($azureNIC.IpConfigurations.Where({$_.publicipaddress.id -eq $azurePublicIP.Id})).PrivateIpAddress
		          
		}
	}
	


$Output_PIP | Export-Csv "Public_IP_Details.csv" -NoTypeInformation -Force



#####################################################################
#    Fetching External Load Balancer Details                        #
#####################################################################

# Iterating over the External Load Balancer List

        $azure_load_balancer_object = $null
        $azure_load_balancer_object = @()

        foreach($AzureLBList_Iterator in $AzureLBList){

        # Populating the cells

			$azureLBPrivateIP = $AzureLBList_Iterator.FrontendIpConfigurations.PrivateIpAddress | out-string
            $azure_load_balancer_object_temp = new-object PSObject

            $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "ResourceGroupName" -Value $AzureLBList_Iterator.ResourceGroupName
            $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "Name" -Value $AzureLBList_Iterator.Name
			$azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "PrivateIP" -Value $azureLBPrivateIP
            $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "Location" -Value $AzureLBList_Iterator.Location
            $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "FrontendIpConfigurationsName" -Value $AzureLBList_Iterator.FrontendIpConfigurations.name
            $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name "BackendAddressPoolsName" -Value $AzureLBList_Iterator.BackendAddressPools.name


            # Back End VM List
            $AzureLBBackendPoolVMs = $AzureLBList_Iterator.BackendAddressPools.BackendIpConfigurations

            $aa
            # Proceed only if $ExternalLBBackendPoolVMs array has data.
            if($AzureLBBackendPoolVMs.count -ne $NULL){

                $AzureLBBackendPoolVMsID_count = 1
                foreach($AzureLBBackendPoolVMs_Iterator in $AzureLBBackendPoolVMs) {
                    #$column_counter = 6

                    if ($null -eq $AzureLBBackendPoolVMs_Iterator) {
                        
                        continue

                    }
                    
                    $AzureLBBackendPoolVMsID_name = "AzureLBBackendPoolVMsID"+$AzureLBBackendPoolVMsID_count
                    $azure_load_balancer_object_temp | add-member -MemberType NoteProperty -Name $AzureLBBackendPoolVMsID_name -Value $AzureLBBackendPoolVMs_Iterator.id
                    $AzureLBBackendPoolVMsID_count += 1
                }

            }

            $azure_load_balancer_object += $azure_load_balancer_object_temp
          
        }

        $azure_load_balancer_object | Export-Csv "Azure_Load_Balancer_details.csv" -NoTypeInformation -Force


#####################################################################
#    Fetching Resource Details                                      #
#####################################################################

	$allResources = $null
	$allResources = @()

    # Iterating through resources under the subscription
		
		foreach ($resource in $resources)
		{
        $customPsObject = New-Object -TypeName PsObject
        $tags = $resource.Tags.Keys + $resource.Tags.Values -join ':'

        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceName -Value $resource.Name
        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $resource.ResourceGroupName
        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceType -Value $resource.ResourceType
        $customPsObject | Add-Member -MemberType NoteProperty -Name Kind -Value $resource.Kind
        $customPsObject | Add-Member -MemberType NoteProperty -Name Location -Value $resource.Location
        $customPsObject | Add-Member -MemberType NoteProperty -Name Tags -Value $tags
        $customPsObject | Add-Member -MemberType NoteProperty -Name Sku -Value $resource.Sku
        $customPsObject | Add-Member -MemberType NoteProperty -Name ResourceId -Value $resource.ResourceId
        $allResources += $customPsObject

		}
	
		$allResources | Export-Csv "Resource_All.csv" -NoTypeInformation -Force
	
	



#####################################################################
#    Fetching Subnet and Route Details                                      #
#####################################################################
	
	#Re-using Azure Subscriptions
	$subs = $subscription_list 

	#Checking if the subscriptions are found or not

		#Creating Output Object
		$results = @()

		#Iterating over various subscriptions
		foreach($sub in $subs)
		{
			$SubscriptionId = $sub.SubscriptionId
			Write-Output $SubscriptionName

			#Selecting the Azure Subscription
			Select-AzureRmSubscription -SubscriptionName $SubscriptionId

			#Getting all Azure Route Tables
			$routeTables = Get-AzureRmRouteTable

			foreach($routeTable in $routeTables)
			{
				$routeTableName = $routeTable.Name
				$routeResourceGroup = $routeTable.ResourceGroupName
				Write-Output $routeName

				#Fetch Route Subnets
				$routeSubnets = $routeTable.Subnets

				foreach($routeSubnet in $routeSubnets)
				{
					$subnetName = $routeSubnet.Name
					Write-Output $subnetName

					$subnetId = $routeSubnet.Id

					###Getting information
					$splitarray = $subnetId.Split('/')
					$subscriptionId = $splitarray[2]
					$vNetResourceGroupName = $splitarray[4]
					$virtualNetworkName = $splitarray[8]
					$subnetName = $splitarray[10]

					$NextHopeType = $routeTables.Routes.NextHopType | Out-String
					$NextHopIpAddress = $routeTables.Routes.NextHopIpAddress | Out-String
					$subnetAddressPrefix = $routeTables.Routes.AddressPrefix | Out-String

					$details = @{            
							routeTableName=$routeTableName
							routeResourceGroup=$routeResourceGroup
							subnetName=$subnetName
							subscriptionId=$subscriptionId
							vNetResourceGroupName=$vNetResourceGroupName
							virtualNetworkName=$virtualNetworkName
							subnetAddressPrefix=$subnetAddressPrefix
							NextHopType=$NextHopeType
							NextHopIpAddress=$NextHopIpAddress
					}                           
					$results += New-Object PSObject -Property $details
                

				}

			}
    }
    
	$results | Export-Csv "Route_test.csv" -NoTypeInformation -Force
	
	
#####################################################################
#    Fetching Backup Details                                        #
#####################################################################

Write-Host "Fetching Backup Details... This will take ~10 mins"

$azure_recovery_services_vault_list = Get-AzureRmRecoveryServicesVault 
 
$backup_details = $null 
$backup_details = @() 
 
foreach($azure_recovery_services_vault_list_iterator in $azure_recovery_services_vault_list){ 
 
    Set-AzureRmRecoveryServicesVaultContext -Vault $azure_recovery_services_vault_list_iterator 
 
    $container_list = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM 
 
    foreach($container_list_iterator in $container_list){ 
 
         
        $backup_item = Get-AzureRmRecoveryServicesBackupItem -Container $container_list_iterator -WorkloadType AzureVM 
        $backup_item_array = ($backup_item.ContainerName).split(';') 
        $backup_item_resource_name = $backup_item_array[1] 
        $backup_item_vm_name = $backup_item_array[2] 
        $backup_item_last_backup_status = $backup_item.LastBackupStatus 
        $backup_item_latest_recovery_point = $backup_item.LatestRecoveryPoint 
 
        $backup_details_temp = New-Object psobject 
 
        $backup_details_temp | Add-Member -MemberType NoteProperty -Name "ResourceGroupName" -Value $backup_item_resource_name 
        $backup_details_temp | Add-Member -MemberType NoteProperty -Name "VMName" -Value $backup_item_vm_name 
        $backup_details_temp | Add-Member -MemberType NoteProperty -Name "VaultName" -Value $azure_recovery_services_vault_list_iterator.Name 
        $backup_details_temp | Add-Member -MemberType NoteProperty -Name "BackupStatus" -Value $backup_item_last_backup_status 
        $backup_details_temp | Add-Member -MemberType NoteProperty -Name "LatestRecoveryPoint" -Value $backup_item_latest_recovery_point 
 
        $backup_details = $backup_details + $backup_details_temp 
 
    } 
 
} 
 
# Exporting the data to csv 
$backup_details | Export-Csv "vm_backup_status.csv" -NoTypeInformation -NoClobber

}

Invoke-GetAzureInventoryFunction