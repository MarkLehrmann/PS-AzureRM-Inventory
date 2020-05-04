# PS-AzureRM-Inventory
Powershell AzureRM script for exporting Azure objects to .CSV files

#          Script: Azure Inventory Script                                           
#            Date: August 13, 2018                                                                     
#          Author: Manjunath

DESCRIPTION:
This script will pull the infrastructure details of the Azure subscriptions. Details will be stored under the folder "c:\AzureInventory"
If you have multiple subscriptions, a separate folder will be created for individual subscription.
CSV files will be created for individual services (Virtual Machines, NSG rules, Storage Account, Virtual Networks, Azure Load Balancers) inside the subscription's directory

Additional arrays and output added by Adam Vogt.

add TenantID to command line to restrict scope to a single tenant. -mtl
