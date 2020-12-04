<#
Disclaimer
	The sample scripts are not supported under any Microsoft standard support program or service. 
	The sample scripts are provided AS IS without warranty of any kind.
	Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability
	or of fitness for a particular purpose.
	The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
	In no event shall Microsoft, its authors, or anyone else involved in the creation, production,
	or delivery of the scripts be liable for any damages whatsoever (including, without limitation,
	damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
	arising out of the use of or inability to use the sample scripts or documentation,
    even if Microsoft has been advised of the possibility of such damages.
    
    .SYNOPSIS
        Author: Marcus Ferreira marcus.ferreira[at]microsoft[dot]com
        Version: 0.1

    .DESCRIPTION
	    This script will read Azure resources via "Azure CLI" and convert resources to Terraform files.
    
    .EXAMPLE
        Run script with -SubscriptionID parameter.

        .\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"
#>

Param(
    [Parameter(Mandatory = $True)]
    $SubscriptionID = ""
)

Write-Host "[$(Get-Date)] Finding resources in subscription $($SubscriptionID)..."
$Resources = az graph query -q  "resources | where subscriptionId == '$SubscriptionID' | order by id asc" --output json --only-show-errors | ConvertFrom-Json

$TFDirectory = "terraform"
$TFMainFile = "main.tf"
$TFResourcesFile = "resources.tf"
$AllRGs = @{ }
$AllNICs = @{ }
$AllSTGs = @{ }
$AllVMs = @{ }
$AllVNets = @{ }
$Global:TFResources = @()
$Global:TFImport = @()
$NL = "`r`n"
$SP2 = "  "

Function GetTFAzProvider() {
    $TF_AzProvider = "provider `"azurerm`" {" + $NL +
    "$($SP2)version = `"~> 2.21`"" + $NL +
    "$($SP2)features {}" + $NL +
    "}" + $NL
    
    Return $TF_AzProvider
}

Function GetTFResourceGroup($Obj) {
    $Global:TFResources += "resource `"azurerm_resource_group`" `"rg_$($Obj.Name)`" {" + $NL +
    "$($SP2)name     = `"$($Obj.Name)`"" + $NL +
    "$($SP2)location = `"$($Obj.Location)`"" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_resource_group.rg_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFStorageAccount($Obj) {
    $Global:TFResources += "resource `"azurerm_storage_account`" `"stg_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                     = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name      = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name)" + $NL +
    "$($SP2)location                 = `"$($Obj.Location)`"" + $NL +
    "$($SP2)account_tier             = `"$($Obj.AccountTier)`"" + $NL +
    "$($SP2)account_replication_type = `"$($Obj.AccountReplicationType)`"" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_storage_account.stg_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFVirtualNetworks($Obj) {
    $Global:TFResources += "resource `"azurerm_virtual_network`" `"vnet_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                     = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name      = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name)" + $NL +
    "$($SP2)location                 = `"$($Obj.Location)`"" + $NL +
    "$($SP2)address_space            = ["

    ForEach ($AddressSpace In $Obj.AddressSpaces) {
        $Global:TFResources += "`"$($AddressSpace.AddressSufixes -join ',')`""
    }
    
    $Global:TFResources += "]" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_virtual_network.vnet_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFSubnets($Obj) {
    $Global:TFResources += "resource `"azurerm_subnet`" `"subnet_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                 = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name  = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name)" + $NL +
    "$($SP2)virtual_network_name = azurerm_virtual_network.vnet_$($Obj.VirtualNetworkName)" + $NL +
    "$($SP2)address_prefixes     = [`"$($Obj.AddressPrefix)`"]" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_subnet.subnet_$($Obj.Name) $($Obj.Id)"     
}

Function GetTFNetInterface($Obj) {
    $Global:TFResources += "resource `"azurerm_network_interface`" `"nic_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name)" + $NL +
    "$($SP2)location            = `"$($Obj.Location)`"" + $NL

    ForEach ($IPConfig In $Obj.IPConfigs) {
        $Split = $IPConfig.subnetId -split '/'
        $SubnetName = $Split[$Split.Count - 1]

        $Global:TFResources += "$($SP2)ip_configuration {" + $NL +
        "$($SP2)$($SP2)name                          = `"$($IPConfig.Name)`"" + $NL +
        "$($SP2)$($SP2)subnet_id                     = azurerm_subnet.subnet_$($SubnetName)" + $NL +
        "$($SP2)$($SP2)private_ip_address_allocation = `"$($IPConfig.privateIPAllocationMethod)`"" + $NL +
        "$($SP2)}"
    }
    
    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_network_interface.nic_$($Obj.Name) $($Obj.Id)"
}

Function GetTFWindowsVM($Obj) {
    $Nics = $Obj.Nics

    $Global:TFResources += "resource `"azurerm_windows_virtual_machine`" `"vm_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                  = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name   = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name)" + $NL +
    "$($SP2)location              = `"$($Obj.Location)`"" + $NL +
    "$($SP2)size                  = `"$($Obj.Size)`"" + $NL +
    "$($SP2)admin_username        = `"$($Obj.Name)`"" + $NL +
    "$($SP2)admin_password        = `"$($Obj.Name)`"" + $NL +
    "$($SP2)network_interface_ids = ["
    
    ForEach ($Nic In $Nics) {
        $Split = $Nic.NicId -split '/'
        $NicName = $Split[$Split.count - 1]
        $Global:TFResources += "azurerm_network_interface.nic_$($NicName)" -join ','
    }
    
    $Global:TFResources += "]" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_windows_virtual_machine.vm_$($Obj.Name) $($Obj.Id)"
}

ForEach ($Resource In $Resources) {
    $Type = $Resource.Type

    Switch ($Type) {
        'microsoft.storage/storageaccounts' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                     = $Resource.Id
                Name                   = $Resource.Name
                Location               = $Resource.location
                ResourceGroup          = [PSCustomObject]@{
                    Id       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name     = $Resource.resourceGroup
                    Location = $Resource.location
                }
                AccountTier            = ($Resource.sku.name -split '_')[0]
                AccountReplicationType = ($Resource.sku.name -split '_')[1]     
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllSTGs.Contains($Obj.Id)) { $AllSTGs.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/virtualnetworks' {
            $Properties = $Resource.Properties
            $AddressSpaces = $Properties.addressSpace
            $Subnets = $Properties.subnets
            $Peerings = $Properties.virtualNetworkPeerings

            $Obj = [PSCustomObject]@{
                Id            = $Resource.Id
                Name          = $Resource.Name
                Location      = $Resource.location
                ResourceGroup = [PSCustomObject]@{
                    Id       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name     = $Resource.resourceGroup
                    Location = $Resource.location
                }
                AddressSpaces = @()
                Subnets       = @()
                Peerings      = @()
            }

            ForEach ($AddressSpace In $AddressSpaces) {
                $Obj.AddressSpaces += [PSCustomObject]@{
                    AddressSufixes = $AddressSpace.addressPrefixes
                }
            }

            ForEach ($Subnet In $Subnets) {
                $SubnetProperties = $Subnet.Properties

                $Obj.Subnets += [PSCustomObject]@{
                    Id                 = $Subnet.id
                    Name               = $Subnet.name
                    AddressPrefix      = $SubnetProperties.addressPrefix
                    ResourceGroup      = [PSCustomObject]@{
                        Id       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                        Name     = $Resource.resourceGroup
                        Location = $Resource.location
                    }
                    VirtualNetworkName = $Resource.Name                 
                }
            }
            
            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllVNets.Contains($Obj.Id)) { $AllVNets.Add($Obj.Id, $Obj) }            
        }

        'microsoft.network/networkinterfaces' {
            $Properties = $Resource.Properties
            $IPConfigs = $Properties.ipConfigurations

            $Obj = [PSCustomObject]@{
                Id            = $Resource.Id
                Name          = $Resource.Name
                Location      = $Resource.location
                ResourceGroup = [PSCustomObject]@{
                    Id       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name     = $Resource.resourceGroup
                    Location = $Resource.location
                }
                IPConfigs     = @()
            }

            ForEach ($IPConfig In $IPConfigs) {
                $IPProperties = $IPConfig.Properties

                $Obj.IPConfigs += [PSCustomObject]@{
                    name                      = $IPConfig.Name
                    privateIPAllocationMethod = $IPProperties.privateIPAllocationMethod
                    privateIPAddress          = $IPProperties.privateIPAddress
                    primary                   = $IPProperties.primary
                    privateIPAddressVersion   = $IPProperties.privateIPAddressVersion
                    subnetId                  = $IPProperties.subnet.Id
                }
            }
            
            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllNICs.Contains($Obj.Id)) { $AllNICs.Add($Obj.Id, $Obj) }            
        }

        'microsoft.compute/virtualmachines' {
            $Properties = $Resource.Properties
            $Nics = $Properties.networkProfile.networkinterfaces

            $Obj = [PSCustomObject]@{
                Id            = $Resource.Id
                Name          = $Resource.Name
                Location      = $Resource.location
                ResourceGroup = [PSCustomObject]@{
                    Id       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name     = $Resource.resourceGroup
                    Location = $Resource.location
                }
                Size          = $Properties.hardwareProfile.vmSize
                Nics          = @()
            }

            ForEach ($Nic In $Nics) {
                $Obj.Nics += [PSCustomObject]@{
                    NicId = $Nic.id
                }                
            }
        
            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllVMs.Contains($Obj.Id)) { $AllVMs.Add($Obj.Id, $Obj) }
        }
    }

    $Type = $null
    $Properties = $null
    $Obj = $null
}

Write-Host "[$(Get-Date)] Generating terraform files..."

$null = New-Item -Name $TFDirectory -Path (Get-Location).Path -Type Directory -Force
$null = New-Item -Name $TFMainFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value (GetTFAzProvider) -Force

$AllRGs.Values | ForEach-Object { GetTFResourceGroup($_) }
$AllSTGs.Values | ForEach-Object { GetTFStorageAccount($_) }
$AllVNets.Values | ForEach-Object { GetTFVirtualNetworks($_) }
$AllVNets.Values.Subnets | ForEach-Object { GetTFSubnets($_) }
$AllNICs.Values | ForEach-Object { GetTFNetInterface($_) }
$AllVMs.Values | ForEach-Object { GetTFWindowsVM($_) }

$null = New-Item -Name $TFResourcesFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFResources -Join $NL) -Force

Write-Host "[$(Get-Date)] Indenting files..."
$null = terraform fmt $TFDirectory