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
        Version: 0.2

    .DESCRIPTION
        This script will read Azure resources via "Azure CLI" and convert resources to Terraform files.
        
        Required: az cli and az graph
                  install az graph with: # az extension add --name resource-graph

        Supported Azure resources:

        resourcegroups
        microsoft.storage/storageaccounts
        microsoft.network/publicipaddresses
        microsoft.network/virtualnetworks
        microsoft.network/virtualnetworks/subnets
        microsoft.network/networkinterfaces
        microsoft.compute/availabilitysets
        microsoft.compute/virtualmachines
        microsoft.compute/disks
    
    .EXAMPLE
        Run script with -SubscriptionID parameter.

        .\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"

        Before importing the resources into Terraform state, set the subscription ID as default.

        # az account set --subscription "<my_subscription_ID>"
#>

Param(
    [Parameter(Mandatory = $True)]
    $SubscriptionID = @()
)

Function CheckDeps() {
    Write-Host "[$(Get-Date)] Checking tool dependencies..."

    $azcli = az --version
    If ($null -eq $azcli) {
        throw "[$(Get-Date)] Azure Cli not found!"
        $host.Exit()
    }

    $azcliExt = az extension list --output json | ConvertFrom-Json
    If ($azcliExt.name -notin 'resource-graph') {
        throw "[$(Get-Date)] Azure CLI Resource graph not found. Please install it with: az extension add --name resource-graph"
        $host.Exit()    
    }

    $tf = terraform version
    If ($null -eq $tf) {
        throw "[$(Get-Date)] Missing Terraform binary. Please download it @ https://www.terraform.io/downloads.html"
        $host.Exit()        
    }
}

CheckDeps

$Resources = @()
$ResourceGroups = @()

Write-Host "[$(Get-Date)] Finding resources in subscription $($SubscriptionID)..."
$Resources = az graph query -q "resources | where subscriptionId == '$SubscriptionID' | order by id asc" --output json --only-show-errors | ConvertFrom-Json
$ResourceGroups = az graph query -q "resourceContainers | where subscriptionId == '$SubscriptionID' | order by id asc" --output json --only-show-errors | ConvertFrom-Json

$TFDirectory = "terraform"
$TFMainFile = "main.tf"
$TFResourcesFile = "resources.tf"
$TFImportFile = "terraform_import.cmd"
$AllRGs = @{ }
$AllNICs = @{ }
$AllSTGs = @{ }
$AllVMs = @{ }
$AllVNets = @{ }
$AllDisks = @{ }
$AllPIPs = @{ }
$AllAVSets = @{ }
$Global:TFResources = @()
$Global:TFImport = @()
$NL = "`r`n"

$Global:TFImport += "terraform init"
$Global:TFImport += "terraform validate"

Function GetTFAzProvider() {
    $TF_AzProvider = "provider `"azurerm`" {" + $NL +
    "  version = `"~> 2.21`"" + $NL +
    "  features {}" + $NL +
    "}" + $NL
    
    Return $TF_AzProvider
}

Function GetTFResourceGroup($Obj) {
    $Global:TFResources += "resource `"azurerm_resource_group`" `"rg_$($Obj.Name)`" {" + $NL +
    "  name     = `"$($Obj.Name)`""

    $RG = $ResourceGroups | Where-Object {$_.id -eq $Obj.Id}

    $Global:TFResources += "  location = `"$($RG.location)`""

    $TagNames = $RG.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($RG.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_resource_group.rg_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFStorageAccount($Obj) {
    $Global:TFResources += "resource `"azurerm_storage_account`" `"stg_$($Obj.Name)`" {" + $NL +
        "  name                     = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name      = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                 = `"$($Obj.Location)`"" + $NL +
        "  account_tier             = `"$($Obj.AccountTier)`"" + $NL +
        "  account_kind             = `"$($Obj.AccountKind)`"" + $NL +
        "  account_replication_type = `"$($Obj.AccountReplicationType)`""

    If ($Obj.AllowBlobPublicAccess) {
        $Global:TFResources += "  allow_blob_public_access = $($Obj.AllowBlobPublicAccess.ToString().ToLower())"
    }

    If ($Obj.MinimumTlsVersion) {
        $Global:TFResources += "  min_tls_version          = `"$($Obj.MinimumTlsVersion)`""
    }

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_storage_account.stg_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFVirtualNetwork($Obj) {
    $Global:TFResources += "resource `"azurerm_virtual_network`" `"vnet_$($Obj.Name)`" {" + $NL +
        "  name                = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location            = `"$($Obj.Location)`"" + $NL +
        "  address_space       = [`"$($Obj.AddressSpaces.AddressSufixes -join '`",`"')`"]" + $NL +
        "  dns_servers         = [`"$($Obj.DnsServers -join '`",`"')`"]"

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_virtual_network.vnet_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFSubnet($Obj) {
    $Global:TFResources += "resource `"azurerm_subnet`" `"subnet_$($Obj.Name)`" {" + $NL +
        "  name                 = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name  = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  virtual_network_name = azurerm_virtual_network.vnet_$($Obj.VirtualNetworkName).name" + $NL +
        "  address_prefixes     = [`"$($Obj.AddressPrefix -join '`",`"')`"]"

    If($Obj.ServiceEndpoints) {
        $Global:TFResources += "  service_endpoints    = [`"$($Obj.ServiceEndpoints.service -join '`",`"')`"]"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_subnet.subnet_$($Obj.Name) $($Obj.Id)"     
}

Function GetTFPublicIP($Obj) {
    $Global:TFResources += "resource `"azurerm_public_ip`" `"pip_$($Obj.Name)`" {" + $NL +
        "  name                    = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name     = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                = `"$($Obj.Location)`"" + $NL +
        "  allocation_method       = `"$($Obj.AllocationMethod)`"" + $NL +
        "  sku                     = `"$($Obj.SkuName)`"" + $NL +
        "  ip_version              = `"$($Obj.PublicIPAddressVersion)`"" + $NL +
        "  idle_timeout_in_minutes = `"$($Obj.IdleTimeoutInMinutes)`""

    If ($Obj.DomainDNSLabel) {
        $Global:TFResources += "  domain_name_label       = `"$($Obj.DomainDNSLabel)`""
    }
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_public_ip.pip_$($Obj.Name) $($Obj.Id)"    
}

Function GetTFAvailSet($Obj) {
    If($Obj.Sku -eq "Aligned") { $IsManaged = $True } Else { $IsManaged = $False }

    $Global:TFResources += "resource `"azurerm_availability_set`" `"avset_$($Obj.Name)`" {" + $NL +
        "  name                         = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name          = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                     = `"$($Obj.Location)`"" + $NL +
        "  managed                      = $($IsManaged.toString().ToLower())" + $NL +
        "  platform_fault_domain_count  = `"$($Obj.PlatformFaultDomainCount)`"" + $NL +
        "  platform_update_domain_count = `"$($Obj.PlatformUpdateDomainCount)`""

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_availability_set.avset_$($Obj.Name) $($Obj.Id)" 
}

Function GetTFNetInterface($Obj) {
    $Global:TFResources += "resource `"azurerm_network_interface`" `"nic_$($Obj.Name)`" {" + $NL +
        "  name                = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location            = `"$($Obj.Location)`"" + $NL

    $I = 1
    ForEach ($IPConfig In $Obj.IPConfigs) {
        $Split = $IPConfig.subnetId -split '/'
        $SubnetName = $Split[$Split.Count - 1]
        $PIP = $AllPIPs.Values | Where-Object {$_.Id -eq $IPConfig.PublicIPId}

        If($I -ne $Obj.IPConfigs.Count) {
            $Global:TFResources += "  ip_configuration {" + $NL +
                "    name                          = `"$($IPConfig.Name)`"" + $NL +
                "    subnet_id                     = azurerm_subnet.subnet_$($SubnetName).id" + $NL +
                "    private_ip_address_allocation = `"$($IPConfig.privateIPAllocationMethod)`""
        
                If($PIP) {
                    $Global:TFResources += "    public_ip_address_id          = azurerm_public_ip.pip_$($PIP.Name).id"
                }

                $Global:TFResources += "  }" + $NL
        } Else {
            $Global:TFResources += "  ip_configuration {" + $NL +
                "    name                          = `"$($IPConfig.Name)`"" + $NL +
                "    subnet_id                     = azurerm_subnet.subnet_$($SubnetName).id" + $NL +
                "    private_ip_address_allocation = `"$($IPConfig.privateIPAllocationMethod)`""

                If($PIP) {
                    $Global:TFResources += "    public_ip_address_id          = azurerm_public_ip.pip_$($PIP.Name).id"
                }

                $Global:TFResources += "  }"
        }

        $I++
    }
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_network_interface.nic_$($Obj.Name) $($Obj.Id)"
}

Function GetTFManagedDisk($Obj) {
    $Global:TFResources += "resource `"azurerm_managed_disk`" `"disk_$($Obj.Name)`" {" + $NL +
        "  name                 = `"$($Obj.Name)`"" + $NL +
        "  location             = `"$($Obj.Location)`"" + $NL +
        "  resource_group_name  = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  storage_account_type = `"$($Obj.StorageAccountType)`"" + $NL +
        "  create_option        = `"$($Obj.CreateOption)`"" + $NL +
        "  disk_size_gb         = `"$($Obj.SizeGB)`""

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_managed_disk.disk_$($Obj.Name) $($Obj.Id)"
}

Function GetTFDataDiskAttachment($Obj) {
    $VM = $Resources | Where-Object {$_.id -eq $Obj.VMId}
    $VMDataDisks = $VM.properties.storageprofile.dataDisks

    $Global:TFResources += "resource `"azurerm_virtual_machine_data_disk_attachment`" `"disk_att_$($Obj.Name)`" {" + $NL +
        "  managed_disk_id    = azurerm_managed_disk.disk_$($Obj.Name).id" + $NL +
        "  virtual_machine_id = azurerm_windows_virtual_machine.vm_$($VM.name).id" + $NL +
        "  lun                = $($VMDataDisks.lun)" + $NL +
        "  caching            = `"$($VMDataDisks.caching)`"" + $NL +
        "}" + $NL

    $DiskAttId = "$($VM.Id)/dataDisks/$($Obj.Name)"
    $Global:TFImport += "terraform import azurerm_virtual_machine_data_disk_attachment.disk_att_$($Obj.Name) $($DiskAttId)"    
}

Function GetTFWindowsVM($Obj) {
    $Nics = $Obj.Nics
    $AvSet = $AllAVSets.Values | Where-Object {$_.Id -eq $Obj.AvailabilitySetId}

    $Global:TFResources += "resource `"azurerm_windows_virtual_machine`" `"vm_$($Obj.Name)`" {" + $NL +
        "  name                  = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name   = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location              = `"$($Obj.Location)`"" + $NL +
        "  size                  = `"$($Obj.Size)`"" + $NL +
        "  admin_username        = `"$($Obj.AdminUsername)`"" + $NL +
        "  admin_password        = `"$($Obj.Name)`"" + $NL +
        "  license_type          = `"$($Obj.LicenseType)`""

    If ($AvSet) {
        $Global:TFResources += "  availability_set_id   = azurerm_availability_set.avset_$($AvSet.Name).id"
    }

    If ($Obj.BootDiagnostics) {
        $Global:TFResources += $NL + "  boot_diagnostics {" + $NL +
        "    storage_account_uri = `"$($Obj.BootDiagnostics)`"" + $NL +
        "  }"
    }
        
    $Global:TFResources += $NL +"  network_interface_ids = ["
    
    ForEach ($Nic In $Nics) {
        $Split = $Nic.NicId -split '/'
        $NicName = $Split[$Split.count - 1]
        $Global:TFResources += "    azurerm_network_interface.nic_$($NicName).id" -join ','
    }
    
    $Global:TFResources += "  ]" + $NL

    $OSDisk = $Obj.Disks | Where-Object {$_.OsType}
    $OsDiskInfo = $Obj.OsDiskInfo

    $Global:TFResources += "  os_disk {" + $NL +
        "    caching              = `"$($OsDiskInfo.caching)`"" + $NL +
        "    storage_account_type = `"$($OSDisk.StorageAccountType)`"" + $NL +
        "    disk_size_gb         = `"$($OSDisk.SizeGB)`"" + $NL +
        "    name                 = `"$($OsDiskInfo.name)`"" + $NL +
        "  }" + $NL

    $Global:TFResources += "  source_image_reference {" + $NL +
        "    publisher = `"$($Obj.Publisher)`"" + $NL +
        "    offer     = `"$($Obj.Offer)`"" + $NL +
        "    sku       = `"$($Obj.Sku)`"" + $NL +
        "    version   = `"$($Obj.Version)`"" + $NL +
        "  }"

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_windows_virtual_machine.vm_$($Obj.Name) $($Obj.Id)"
}

ForEach ($Resource In $Resources) {
    $Type = $Resource.Type

    Switch ($Type) {
        'microsoft.compute/availabilitysets' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                        = $Resource.Id
                Name                      = $Resource.Name
                Location                  = $Resource.location
                ResourceGroup             = [PSCustomObject]@{
                    Id          	      = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name                  = $Resource.resourceGroup
                }
                Sku                       = $Resource.sku.name
                PlatformFaultDomainCount  = $Properties.platformFaultDomainCount
                PlatformUpdateDomainCount = $Properties.platformUpdateDomainCount
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllAVSets.Contains($Obj.Id)) { $AllAVSets.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/publicipaddresses' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                     = $Resource.Id
                Name                   = $Resource.Name
                Location               = $Resource.location
                ResourceGroup          = [PSCustomObject]@{
                    Id          	   = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name               = $Resource.resourceGroup
                }
                AllocationMethod       = $Properties.publicIPAllocationMethod
                IpAddress              = $Properties.ipAddress
                IdleTimeoutInMinutes   = $Properties.idleTimeoutInMinutes
                PublicIPAddressVersion = $Properties.publicIPAddressVersion
                SkuName                = $Resource.sku.name
                SkuTier                = $Resource.sku.tier
                DomainDNSLabel         = $Properties.dnsSettings.domainNameLabel
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllPIPs.Contains($Obj.Id)) { $AllPIPs.Add($Obj.Id, $Obj) }
        }

        'microsoft.storage/storageaccounts' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                     = $Resource.Id
                Name                   = $Resource.Name
                Location               = $Resource.location
                ResourceGroup          = [PSCustomObject]@{
                    Id          	   = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name               = $Resource.resourceGroup
                }
                AccountTier            = ($Resource.sku.name -split '_')[0]
                AccountReplicationType = ($Resource.sku.name -split '_')[1]
                AccountKind            = $Resource.kind
                Tags                   = $Resource.tags
                MinimumTlsVersion      = $Properties.minimumTlsVersion
                AllowBlobPublicAccess  = $Properties.allowBlobPublicAccess
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
                    Id        = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name      = $Resource.resourceGroup
                }
                DnsServers    = $Properties.dhcpOptions.dnsServers
                Tags          = $Resource.tags
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
                        Id             = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                        Name           = $Resource.resourceGroup
                    }
                    VirtualNetworkName = $Resource.Name
                    ServiceEndpoints   = $SubnetProperties.serviceEndpoints          
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
                    Id        = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name      = $Resource.resourceGroup
                }
                Tags          = $Resource.tags
                IPConfigs     = @()
            }

            ForEach ($IPConfig In $IPConfigs) {
                $IPProperties = $IPConfig.Properties

                $Obj.IPConfigs += [PSCustomObject]@{
                    Name                      = $IPConfig.Name
                    PrivateIPAllocationMethod = $IPProperties.privateIPAllocationMethod
                    PrivateIPAddress          = $IPProperties.privateIPAddress
                    Primary                   = $IPProperties.primary
                    PrivateIPAddressVersion   = $IPProperties.privateIPAddressVersion
                    SubnetId                  = $IPProperties.subnet.id
                    PublicIPId                = $IPProperties.publicIPAddress.id
                }
            }
            
            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllNICs.Contains($Obj.Id)) { $AllNICs.Add($Obj.Id, $Obj) }            
        }

        'microsoft.compute/virtualmachines' {
            $Properties = $Resource.Properties
            $Nics = $Properties.networkProfile.networkinterfaces
            $StorageProfile = $Properties.storageProfile
            $DiagProfile = $Properties.diagnosticsProfile
            $ImageReference = $StorageProfile.imagereference
            $OsDiskInfo = $StorageProfile.osDisk
            $DiskResources = $Resources | Where-Object {$_.Type -eq 'microsoft.compute/disks'}
            $VMDisks = $DiskResources | Where-Object {$_.managedBy -eq $Resource.Id}

            $Obj = [PSCustomObject]@{
                Id                = $Resource.Id
                Name              = $Resource.Name
                Location          = $Resource.location
                ResourceGroup     = [PSCustomObject]@{
                    Id            = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name          = $Resource.resourceGroup
                }
                Size              = $Properties.hardwareProfile.vmSize
                Nics              = @()
                Disks             = @()
                AdminUsername     = $Properties.osProfile.adminUsername
                Publisher         = $ImageReference.publisher
                Offer             = $ImageReference.offer
                Sku               = $ImageReference.sku
                Version           = $ImageReference.version
                LicenseType       = $Properties.licenseType
                BootDiagnostics   = $DiagProfile.bootDiagnostics.storageUri
                AvailabilitySetId = $Properties.availabilitySet.Id
                OsDiskInfo        = $OSDiskInfo
            }

            ForEach ($Nic In $Nics) {
                $Obj.Nics += [PSCustomObject]@{
                    NicId = $Nic.id
                }                
            }

            ForEach($VMDisk In $VMDisks) {
                $Obj.Disks += [PSCustomObject]@{
                    Id                 = $VMDisk.id
                    Name               = $VMDisk.name
                    Location           = $VMDisk.location
                    VMId               = $VMDisk.managedBy
                    SizeGB             = $VMDisk.properties.diskSizeGB
                    State              = $VMDisk.properties.diskState
                    OsType             = $VMDisk.properties.osType
                    StorageAccountType = $VMDisk.sku.name
                    CreateOption       = $VMDisk.properties.creationData.createOption
                    ResourceGroup      = [PSCustomObject]@{
                        Id             = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                        Name           = $Resource.resourceGroup
                    }            
                }
            }

            $DataDisks = $Obj.Disks | Where-Object {-Not $_.OsType}

            ForEach($DataDisk In $DataDisks) {
                If (-Not $AllDisks.Contains($DataDisk.Id)) { $AllDisks.Add($DataDisk.Id, $DataDisk) }
            }
            
            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllVMs.Contains($Obj.Id)) { $AllVMs.Add($Obj.Id, $Obj) }
        }

        'microsoft.compute/disks' {
            If (-Not $Resource.properties.osType) {
                $Obj = [PSCustomObject]@{
                    Id            = $Resource.Id
                    Name          = $Resource.Name
                    Location      = $Resource.location
                    ResourceGroup = [PSCustomObject]@{
                        Id        = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                        Name      = $Resource.resourceGroup
                    }
                    VMId               = $Resource.managedBy
                    SizeGB             = $Resource.properties.diskSizeGB
                    State              = $Resource.properties.diskState
                    OsType             = $Resource.properties.osType
                    StorageAccountType = $Resource.sku.name
                    CreateOption       = $Resource.properties.creationData.createOption                            
                }          

                If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
                If (-Not $AllDisks.Contains($Obj.Id)) { $AllDisks.Add($Obj.Id, $Obj) }
            }
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
$AllAVSets.Values | ForEach-Object { GetTFAvailSet($_) }
$AllVNets.Values | ForEach-Object { GetTFVirtualNetwork($_) }
$AllVNets.Values.Subnets | ForEach-Object { GetTFSubnet($_) }
$AllPIPs.Values | ForEach-Object { GetTFPublicIP($_) }
$AllNICs.Values | ForEach-Object { GetTFNetInterface($_) }
$AllDisks.Values | ForEach-Object { GetTFManagedDisk($_) }
$AllVMs.Values | ForEach-Object { GetTFWindowsVM($_) }
$AllDisks.Values | Where-Object {$_.VMId} | ForEach-Object { GetTFDataDiskAttachment($_) }

$null = New-Item -Name $TFResourcesFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFResources -Join $NL) -Force

Write-Host "[$(Get-Date)] Indenting files..."
$null = terraform fmt $TFDirectory

Write-Host "[$(Get-Date)] Generating import file..."
$null = New-Item -Name $TFImportFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFImport -Join $NL) -Force