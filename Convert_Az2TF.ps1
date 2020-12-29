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
        Version: 0.5

    .DESCRIPTION
        This script will read Azure resources via "Azure CLI" and convert resources to Terraform files.
        
        Required: az cli, az cli graph extension and Terraform binary.

                  install az cli graph with: # az extension add --name resource-graph

        Supported Azure resources:

        resourcegroups
        microsoft.storage/storageaccounts
        microsoft.network/publicipaddresses
        microsoft.network/networksecuritygroups
        microsoft.network/virtualnetworks
        microsoft.network/virtualnetworks/subnets
        microsoft.network/networkinterfaces
        microsoft.network/connections
        microsoft.network/localnetworkgateways
        microsoft.network/virtualnetworkgateways
        microsoft.network/routetables
        microsoft.compute/availabilitysets
        microsoft.compute/virtualmachines (Windows so far)
        microsoft.compute/disks
        microsoft.keyvault/vaults
    
    .EXAMPLE
        Run script with -SubscriptionID parameter.

        .\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"

        Before importing the resources into Terraform state, set the subscription ID as default.

        # az account list -o table
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
$AllGWs = @{ }
$AllLocalGWs = @{ }
$AllGWConnections = @{ }
$AllKeyVaults = @{ }
$AllLogWks = @{ }
$AllNSGs = @{ }
$AllRouteTables = @{ }
$Global:TFResources = @()
$Global:TFImport = @()
$NL = "`r`n"

$Global:TFImport += "terraform init"
$Global:TFImport += "terraform validate"

Function GetTFAzProvider() {
    $TF_AzProvider = "provider `"azurerm`" {" + $NL +
    "  features {}" + $NL +
    "}" + $NL
    
    Return $TF_AzProvider
}

Function GetTFResourceGroup($Obj) {
    $Global:TFResources += "resource `"azurerm_resource_group`" `"rg_$($Obj.Name)`" {" + $NL +
    "  name     = `"$($Obj.Name)`""

    $RG = $ResourceGroups | Where-Object {$_.id -eq $Obj.Id}

    $Global:TFResources += "  location = `"$($RG.location)`""

    $TagNames = $RG.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

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

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

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

Function GetTFGatewayConnection($Obj) {
    $LocalGW = $AllLocalGWs.Values | Where-Object {$_.Id -eq $Obj.LocalNetworkGatewayId}
    $Gateway = $AllGWs.Values | Where-Object {$_.Id -eq $Obj.VirtualNetworkGatewayId}
        
    $Global:TFResources += "resource `"azurerm_virtual_network_gateway_connection`" `"gwcon_$($Obj.Name)`" {" + $NL +
    "  name                         = `"$($Obj.Name)`"" + $NL +
    "  resource_group_name          = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
    "  location                     = `"$($Obj.Location)`"" + $NL +
    "  type                         = `"$($Obj.Type)`"" + $NL +
    "  virtual_network_gateway_id   = azurerm_virtual_network_gateway.gw_$($Gateway.Name).id" + $NL +
    "  local_network_gateway_id     = azurerm_local_network_gateway.lgw_$($LocalGW.Name).id" + $NL +
    "  connection_protocol          = `"$($Obj.Protocol)`"" + $NL +
    "  enable_bgp                   = $($Obj.EnableBgp.ToString().ToLower())" + $NL +
    "  routing_weight               = `"$($Obj.RoutingWeight)`"" + $NL +
    "  express_route_gateway_bypass = $($Obj.ExpressRouteGatewayBypass.ToString().ToLower())" + $NL +
    "  dpd_timeout_seconds          = `"$($Obj.DpdTimeoutSeconds)`"" + $NL +
    "  shared_key                   = `"$($Obj.SharedKey)`""

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_virtual_network_gateway_connection.gwcon_$($Obj.Name) $($Obj.Id)"
}

Function GetTFLocalGateway($Obj) {
    $Global:TFResources += "resource `"azurerm_local_network_gateway`" `"lgw_$($Obj.Name)`" {" + $NL +
    "  name                = `"$($Obj.Name)`"" + $NL +
    "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
    "  location            = `"$($Obj.Location)`"" + $NL +
    "  gateway_address     = `"$($Obj.GatewayIPAddress)`"" + $NL +
    "  address_space       = [`"$($Obj.AddressPrefixes -join '`",`"')`"]"
    
    If ($Obj.BgpSettings.asn) {
        $Global:TFResources += $NL + "  bgp_settings {" + $NL +
            "    asn                 = `"$($Obj.BgpSettings.asn)`"" + $NL +
            "    bgp_peering_address = `"$($Obj.BgpSettings.bgpPeeringAddress)`"" + $NL +
            "    peer_weight         = `"$($Obj.BgpSettings.peerWeight)`""

        $Global:TFResources += "  }"
    }
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_local_network_gateway.lgw_$($Obj.Name) $($Obj.Id)"
}

Function GetTFVirtualGateway($Obj) {
    $Global:TFResources += "resource `"azurerm_virtual_network_gateway`" `"gw_$($Obj.Name)`" {" + $NL +
    "  name                = `"$($Obj.Name)`"" + $NL +
    "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
    "  location            = `"$($Obj.Location)`"" + $NL +
    "  type                = `"$($Obj.Type)`"" + $NL +
    "  vpn_type            = `"$($Obj.VpnType)`"" + $NL +
    "  active_active       = $($Obj.ActiveActive.ToString().ToLower())" + $NL +
    "  enable_bgp          = $($Obj.EnableBGP.ToString().ToLower())" + $NL +
    "  generation          = `"$($Obj.VPNGatewayGeneration)`"" + $NL +
    "  sku                 = `"$($Obj.Sku)`""             

    $I = 1
    ForEach ($IPConfig In $Obj.IPConfigs) {
        $PIP = $AllPIPs.Values | Where-Object {$_.Id -eq $IPConfig.PublicIPId}
        $Split = $IPConfig.SubnetId -split '/'
        $SubnetName = "$($Split[$Split.Count - 3])_$($Split[$Split.Count - 1])"

        If($I -ne $Obj.IPConfigs.Count) {
            $Global:TFResources += $NL + "  ip_configuration {" + $NL +
                "    name                          = `"$($IPConfig.Name)`"" + $NL +
                "    public_ip_address_id          = azurerm_public_ip.pip_$($PIP.Name).id" + $NL +
                "    private_ip_address_allocation = `"$($IPConfig.PrivateIPAllocationMethod)`"" + $NL +
                "    subnet_id                     = azurerm_subnet.subnet_$($SubnetName).id"

            $Global:TFResources += "  }" + $NL
        } Else {
            $Global:TFResources += $NL + "  ip_configuration {" + $NL +
                "    name                          = `"$($IPConfig.Name)`"" + $NL +
                "    public_ip_address_id          = azurerm_public_ip.pip_$($PIP.Name).id" + $NL +
                "    private_ip_address_allocation = `"$($IPConfig.PrivateIPAllocationMethod)`"" + $NL +
                "    subnet_id                     = azurerm_subnet.subnet_$($SubnetName).id"

            $Global:TFResources += "  }"
        }

        $I++
    }

    If ($Obj.EnableBGP -eq "True") {
        $Global:TFResources += $NL + "  bgp_settings {" + $NL +
            "    asn             = `"$($Obj.BgpSettings.asn)`"" + $NL +
            "    peering_address = `"$($Obj.BgpSettings.bgpPeeringAddress)`"" + $NL +
            "    peer_weight     = `"$($Obj.BgpSettings.peerWeight)`""

        $Global:TFResources += "  }"
    }

    If ($Obj.ClientConfiguration) {
        $Global:TFResources += $NL + "  vpn_client_configuration {" + $NL +
            "    address_space        = [`"$($Obj.ClientConfiguration.vpnClientAddressPool.addressPrefixes -join '`",`"')`"]" + $NL +
            "    aad_tenant           = `"$($Obj.ClientConfiguration.aadTenant)`"" + $NL +
            "    aad_audience         = `"$($Obj.ClientConfiguration.aadAudience)`"" + $NL +
            "    aad_issuer           = `"$($Obj.ClientConfiguration.aadIssuer)`"" + $NL +
            "    vpn_client_protocols = [`"$($Obj.ClientConfiguration.vpnClientProtocols -join '`",`"')`"]"

        $Global:TFResources += "  }"
    }
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_virtual_network_gateway.gw_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFVirtualNetwork($Obj) {
    $Global:TFResources += "resource `"azurerm_virtual_network`" `"vnet_$($Obj.Name)`" {" + $NL +
        "  name                = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location            = `"$($Obj.Location)`"" + $NL +
        "  address_space       = [`"$($Obj.AddressSpaces.AddressSufixes -join '`",`"')`"]"

    If ($Obj.DnsServers) {
        $Global:TFResources += "  dns_servers         = [`"$($Obj.DnsServers -join '`",`"')`"]"
    }

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_virtual_network.vnet_$($Obj.Name) $($Obj.Id)"
    
    If ($Obj.Peerings) {
        ForEach($Peering In $Obj.Peerings) {
            $Split = $Peering.RemoteVirtualNetwork.id -split '/'
            $RemoteVnetName = $Split[$Split.Count - 1]
            $RemoteVnetSubId = $Split[$Split.Count - 7]

            $Global:TFResources += "resource `"azurerm_virtual_network_peering`" `"peering_$($Peering.Name)`" {" + $NL +
            "  name                         = `"$($Peering.Name)`"" + $NL +
            "  resource_group_name          = azurerm_resource_group.rg_$($Peering.ResourceGroup.Name).name" + $NL +
            "  virtual_network_name         = azurerm_virtual_network.vnet_$($Obj.Name).name" + $NL +
            "  allow_virtual_network_access = $($Peering.AllowVirtualNetworkAccess.ToString().ToLower())" + $NL +
            "  allow_forwarded_traffic      = $($Peering.AllowForwardedTraffic.ToString().ToLower())" + $NL +
            "  allow_gateway_transit        = $($Peering.AllowGatewayTransit.ToString().ToLower())" + $NL +
            "  use_remote_gateways          = $($Peering.UseRemoteGateways.ToString().ToLower())"

            If ($RemoteVnetSubId -eq $Peering.SubscriptionId) {
                $Global:TFResources += "  remote_virtual_network_id = azurerm_virtual_network.vnet_$($RemoteVnetName).id"
            } Else {
                $Global:TFResources += "  remote_virtual_network_id = `"$($Peering.RemoteVirtualNetwork.id)`""
            }

            $Global:TFResources += "}" + $NL

            $Global:TFImport += "terraform import azurerm_virtual_network_peering.peering_$($Peering.Name) $($Peering.Id)"
        }
    }    
}

Function GetTFSubnet($Obj) {
    $SubnetName = "$($Obj.VirtualNetworkName)_$($Obj.Name)"

    $Global:TFResources += "resource `"azurerm_subnet`" `"subnet_$($SubnetName)`" {" + $NL +
        "  name                 = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name  = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  virtual_network_name = azurerm_virtual_network.vnet_$($Obj.VirtualNetworkName).name" + $NL +
        "  address_prefixes     = [`"$($Obj.AddressPrefix -join '`",`"')`"]"

    If($Obj.ServiceEndpoints) {
        $Global:TFResources += "  service_endpoints    = [`"$($Obj.ServiceEndpoints.service -join '`",`"')`"]"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_subnet.subnet_$($SubnetName) $($Obj.Id)"     
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
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

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
        "  managed                      = $($IsManaged.ToString().ToLower())" + $NL +
        "  platform_fault_domain_count  = `"$($Obj.PlatformFaultDomainCount)`"" + $NL +
        "  platform_update_domain_count = `"$($Obj.PlatformUpdateDomainCount)`""

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

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

Function GetTFNetSecurityGroup($Obj) {
    $Global:TFResources += "resource `"azurerm_network_security_group`" `"nsg_$($Obj.Name)`" {" + $NL +
        "  name                = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location            = `"$($Obj.Location)`""

    ForEach($SecurityRule In $Obj.SecurityRules) {
        $RuleProperties = $SecurityRule.properties

        $Global:TFResources += $NL + "  security_rule {" + $NL +
        "   name                       = `"$($SecurityRule.name)`"" + $NL +
        "   priority                   = `"$($RuleProperties.priority)`"" + $NL +
        "   direction                  = `"$($RuleProperties.direction)`"" + $NL +
        "   access                     = `"$($RuleProperties.access)`"" + $NL +
        "   protocol                   = `"$($RuleProperties.protocol)`"" + $NL +
        "   source_port_range          = `"$($RuleProperties.sourcePortRange)`"" + $NL +
        "   destination_port_range     = `"$($RuleProperties.destinationPortRange)`"" + $NL +
        "   source_address_prefix      = `"$($RuleProperties.sourceAddressPrefix)`"" + $NL +
        "   destination_address_prefix = `"$($RuleProperties.destinationAddressPrefix)`""

        If ($RuleProperties.description) {
            $Global:TFResources += "   description = `"$($RuleProperties.description)`""
        }

        $Global:TFResources += "  }"
    }

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_network_security_group.nsg_$($Obj.Name) $($Obj.Id)"

    If ($Obj.NicAssociation) {
        ForEach($NicAssociation In $Obj.NicAssociation) {
            $Global:TFResources += "resource `"azurerm_network_interface_security_group_association`" `"nic_nsg_$($NicAssociation.NicName)_$($NicAssociation.NSGName)`" {" + $NL +
            "  network_interface_id      = azurerm_network_interface.nic_$($NicAssociation.NicName).id" + $NL +
            "  network_security_group_id = azurerm_network_security_group.nsg_$($NicAssociation.NSGName).id"

            $Global:TFResources += "}" + $NL

            $Global:TFImport += "terraform import azurerm_network_interface_security_group_association.nic_nsg_$($NicAssociation.NicName)_$($NicAssociation.NSGName) `"$($NicAssociation.NicId)|$($NicAssociation.NSGId)`""
        }
    }

    If ($Obj.SubnetAssociation) {
        ForEach($SubnetAssociation In $Obj.SubnetAssociation) {
            $Global:TFResources += "resource `"azurerm_subnet_network_security_group_association`" `"subnet_nsg_$($SubnetAssociation.SubnetName)_$($SubnetAssociation.NSGName)`" {" + $NL +
            "  subnet_id                 = azurerm_subnet.subnet_$($SubnetAssociation.SubnetName).id" + $NL +
            "  network_security_group_id = azurerm_network_security_group.nsg_$($SubnetAssociation.NSGName).id"

            $Global:TFResources += "}" + $NL

            $Global:TFImport += "terraform import azurerm_subnet_network_security_group_association.subnet_nsg_$($SubnetAssociation.SubnetName)_$($SubnetAssociation.NSGName) $($SubnetAssociation.SubnetId)"
        }
    }    
}

Function GetTFRouteTable($Obj) {
    $Global:TFResources += "resource `"azurerm_route_table`" `"rt_$($Obj.Name)`" {" + $NL +
        "  name                          = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name           = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                      = `"$($Obj.Location)`"" + $NL +
        "  disable_bgp_route_propagation = $($Obj.DisableBgpRoutePropagation.ToString().ToLower())"
    
    ForEach($Route In $Obj.Routes) {
        $RouteProperties = $Route.properties

        $Global:TFResources += $NL + "  route {" + $NL +
        "   name           = `"$($Route.name)`"" + $NL +
        "   address_prefix = `"$($RouteProperties.addressPrefix)`"" + $NL +
        "   next_hop_type  = `"$($RouteProperties.nextHopType)`""

        If ($RouteProperties.nextHopType.ToString().Trim() -eq "VirtualAppliance") {
            $Global:TFResources += "   next_hop_in_ip_address = `"$($RouteProperties.nextHopIpAddress)`""
        }

        $Global:TFResources += "  }"
    }        

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_route_table.rt_$($Obj.Name) $($Obj.Id)"

    If ($Obj.SubnetAssociation) {
        ForEach($SubnetAssociation In $Obj.SubnetAssociation) {
            $Global:TFResources += "resource `"azurerm_subnet_route_table_association`" `"subnet_rt_$($SubnetAssociation.SubnetName)_$($SubnetAssociation.RouteTableName)`" {" + $NL +
            "  subnet_id      = azurerm_subnet.subnet_$($SubnetAssociation.SubnetName).id" + $NL +
            "  route_table_id = azurerm_route_table.rt_$($SubnetAssociation.RouteTableName).id"

            $Global:TFResources += "}" + $NL

            $Global:TFImport += "terraform import azurerm_subnet_route_table_association.subnet_rt_$($SubnetAssociation.SubnetName)_$($SubnetAssociation.RouteTableName) $($SubnetAssociation.SubnetId)"
        }
    }   
}

Function GetTFNetInterface($Obj) {
    $Global:TFResources += "resource `"azurerm_network_interface`" `"nic_$($Obj.Name)`" {" + $NL +
        "  name                = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location            = `"$($Obj.Location)`""

    If ($Obj.AcceleratedNetworking) {
        $Global:TFResources += "  enable_accelerated_networking = $($Obj.AcceleratedNetworking.ToString().ToLower())"
    }

    If ($Obj.IPForwarding) {
        $Global:TFResources += "  enable_ip_forwarding = $($Obj.IPForwarding.ToString().ToLower())"
    }

    ForEach ($IPConfig In $Obj.IPConfigs) {
        $Split = $IPConfig.subnetId -split '/'
        $SubnetName = "$($Split[$Split.Count - 3])_$($Split[$Split.Count - 1])"
        $PIP = $AllPIPs.Values | Where-Object {$_.Id -eq $IPConfig.PublicIPId}

        $Global:TFResources += $NL + "  ip_configuration {" + $NL +
            "    name                          = `"$($IPConfig.Name)`"" + $NL +
            "    subnet_id                     = azurerm_subnet.subnet_$($SubnetName).id" + $NL +
            "    private_ip_address_allocation = `"$($IPConfig.privateIPAllocationMethod)`""
    
            If($PIP) {
                $Global:TFResources += "    public_ip_address_id          = azurerm_public_ip.pip_$($PIP.Name).id"
            }

            $Global:TFResources += "  }"
    }
    
    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

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

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_managed_disk.disk_$($Obj.Name) $($Obj.Id)"
}

Function GetTFDataDiskAttachment($Obj) {
    $VM = $Resources | Where-Object {$_.id -eq $Obj.VMId}
    $VMOsProfile = $VM.properties.osProfile
    $DataDisks = $VM.properties.storageprofile.datadisks
    $VMDataDisk = $DataDisks | Where-Object {$_.managedDisk.id -eq $Obj.Id}

    $Global:TFResources += "resource `"azurerm_virtual_machine_data_disk_attachment`" `"disk_att_$($Obj.Name)`" {" + $NL +
        "  managed_disk_id    = azurerm_managed_disk.disk_$($Obj.Name).id"

    If ($VMOsProfile.windowsConfiguration) {
        $Global:TFResources += "  virtual_machine_id = azurerm_windows_virtual_machine.wvm_$($VM.name).id"
    } Else {
        $Global:TFResources += "  virtual_machine_id = azurerm_linux_virtual_machine.lvm_$($VM.name).id"
    }

    $Global:TFResources += "  lun                = $($VMDataDisk.lun)" + $NL +
        "  caching            = `"$($VMDataDisk.caching)`"" + $NL +
        "}" + $NL

    $DiskAttId = "$($VM.Id)/dataDisks/$($Obj.Name)"
    $Global:TFImport += "terraform import azurerm_virtual_machine_data_disk_attachment.disk_att_$($Obj.Name) $($DiskAttId)"    
}

Function GetTFLinuxVM($Obj) {
    $Nics = $Obj.Nics
    $AvSet = $AllAVSets.Values | Where-Object {$_.Id -eq $Obj.AvailabilitySetId}
    $LinuxConfig = $Obj.OsProfile.linuxConfiguration

    $Global:TFResources += "resource `"azurerm_linux_virtual_machine`" `"lvm_$($Obj.Name)`" {" + $NL +
        "  name                  = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name   = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location              = `"$($Obj.Location)`"" + $NL +
        "  size                  = `"$($Obj.Size)`"" + $NL +
        "  admin_username        = `"$($Obj.AdminUsername)`""

    If ($LinuxConfig.disablePasswordAuthentication.ToString().Trim() -eq "False") {
        $Global:TFResources += "  admin_password        = `"$($Obj.Name)`"" + $NL +
        "  disable_password_authentication = false"
    }

    If ($Obj.Priority -eq "Spot") {
        $Global:TFResources += "  priority = `"$($Obj.Priority)`"" + $NL +
            "  eviction_policy = `"$($Obj.EvictionPolicy)`""
    }
    
    If ($AvSet) {
        $Global:TFResources += "  availability_set_id   = azurerm_availability_set.avset_$($AvSet.Name).id"
    }

    If ($LinuxConfig.ssh.publicKeys) {
        $Global:TFResources += "  admin_ssh_key {" + $NL +
        "    username   = `"$($Obj.AdminUsername)`"" + $NL +
        "    public_key = `"$($LinuxConfig.ssh.publicKeys)`"" + $NL +
        "  }" + $NL        
    }  

    If ($Obj.BootDiagnostics.enabled) {
        $Global:TFResources += $NL + "  boot_diagnostics {"

        If ($Obj.BootDiagnostics.storageUri) {
            $Global:TFResources += "    storage_account_uri = `"$($Obj.BootDiagnostics.storageUri)`""
        }

        $Global:TFResources += "  }"
    }

    $NicNames = @()

    ForEach ($Nic In $Nics) {
        $NicObj = $AllNICs.Values | Where-Object {$_.id -eq $Nic.NicId}
        $NicNames += "azurerm_network_interface.nic_$($NicObj.Name).id"
    }

    $Global:TFResources += $NL + "  network_interface_ids = [$($NicNames -join ',')]" + $NL

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

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_linux_virtual_machine.lvm_$($Obj.Name) $($Obj.Id)"
}

Function GetTFWindowsVM($Obj) {
    $Nics = $Obj.Nics
    $AvSet = $AllAVSets.Values | Where-Object {$_.Id -eq $Obj.AvailabilitySetId}

    $Global:TFResources += "resource `"azurerm_windows_virtual_machine`" `"wvm_$($Obj.Name)`" {" + $NL +
        "  name                  = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name   = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location              = `"$($Obj.Location)`"" + $NL +
        "  size                  = `"$($Obj.Size)`"" + $NL +
        "  admin_username        = `"$($Obj.AdminUsername)`"" + $NL +
        "  admin_password        = `"$($Obj.Name)`"" + $NL +
        "  license_type          = `"$($Obj.LicenseType)`""

    If ($Obj.Priority -eq "Spot") {
        $Global:TFResources += "  priority = `"$($Obj.Priority)`"" + $NL +
            "  eviction_policy = `"$($Obj.EvictionPolicy)`""
    }
    
    If ($AvSet) {
        $Global:TFResources += "  availability_set_id   = azurerm_availability_set.avset_$($AvSet.Name).id"
    }

    If ($Obj.BootDiagnostics.enabled) {
        $Global:TFResources += $NL + "  boot_diagnostics {"

        If ($Obj.BootDiagnostics.storageUri) {
            $Global:TFResources += "    storage_account_uri = `"$($Obj.BootDiagnostics.storageUri)`""
        }

        $Global:TFResources += "  }"
    }

    $NicNames = @()

    ForEach ($Nic In $Nics) {
        $NicObj = $AllNICs.Values | Where-Object {$_.id -eq $Nic.NicId}
        $NicNames += "azurerm_network_interface.nic_$($NicObj.Name).id"
    }

    $Global:TFResources += $NL + "  network_interface_ids = [$($NicNames -join ',')]" + $NL

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

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_windows_virtual_machine.wvm_$($Obj.Name) $($Obj.Id)"
}

Function GetTFKeyVault($Obj) {
    $Global:TFResources += "resource `"azurerm_key_vault`" `"kvault_$($Obj.Name)`" {" + $NL +
        "  name                            = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name             = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                        = `"$($Obj.Location)`"" + $NL +
        "  enabled_for_disk_encryption     = $($Obj.EnabledForDiskEncryption.ToString().ToLower())" + $NL +
        "  enabled_for_deployment          = $($Obj.EnabledForDeployment.ToString().ToLower())" + $NL +
        "  enabled_for_template_deployment = $($Obj.EnabledForTemplateDeployment.ToString().ToLower())" + $NL +
        "  tenant_id                       = `"$($Obj.TenantID)`"" + $NL +
        "  sku_name                        = `"$($Obj.SkuName.ToString().ToLower())`""

    If ($Obj.SoftDeleteRetentionInDays) {
        $Global:TFResources += "  soft_delete_enabled         = true" + $NL +
            "  soft_delete_retention_days  = `"$($Obj.SoftDeleteRetentionInDays)`""
    }

    ForEach($AccessPolicy In $Obj.AccessPolicies) {
        $Global:TFResources += $NL + "  access_policy {" + $NL +
        "   tenant_id = `"$($AccessPolicy.tenantId)`"" + $NL +
        "   object_id = `"$($AccessPolicy.objectId)`"" + $NL + $NL +
        "   key_permissions = [" + $NL +
        "    `"$($AccessPolicy.permissions.keys -join '`",`"')`"" + $NL +
        "   ]" + $NL + $NL +
        "   secret_permissions = [" + $NL +
        "    `"$($AccessPolicy.permissions.secrets -join '`",`"')`"" + $NL +    
        "   ]" + $NL + $NL +     
        "   certificate_permissions = [" + $NL +
        "    `"$($AccessPolicy.permissions.certificates -join '`",`"')`"" + $NL +    
        "   ]" + $NL +
        "  }"
    }

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_key_vault.kvault_$($Obj.Name) $($Obj.Id)"
}

Function GetTFLogWorkspace($Obj) {
    If ($Obj.PublicNetworkAccessForIngestion.ToString() -eq "Enabled") { $InternetIngestionEnabled = $True } Else { $InternetIngestionEnabled = $False }
    If ($Obj.PublicNetworkAccessForQuery.ToString() -eq "Enabled") { $InternetQueryEnabled = $True } Else { $InternetQueryEnabled = $False }

    $Global:TFResources += "resource `"azurerm_log_analytics_workspace`" `"lwks_$($Obj.Name)`" {" + $NL +
        "  name                       = `"$($Obj.Name)`"" + $NL +
        "  resource_group_name        = azurerm_resource_group.rg_$($Obj.ResourceGroup.Name).name" + $NL +
        "  location                   = `"$($Obj.Location)`"" + $NL +
        "  sku                        = `"$($Obj.SkuName)`"" + $NL +
        "  retention_in_days          = `"$($Obj.RetentionInDays)`"" + $NL +
        "  internet_ingestion_enabled = $($InternetIngestionEnabled.ToString().ToLower())" + $NL +
        "  internet_query_enabled     = $($InternetQueryEnabled.ToString().ToLower())"

    If($Obj.WorkspaceCapping.dailyQuotaGb -gt 0){
        $Global:TFResources += "  daily_quota_gb             = `"$($Obj.WorkspaceCapping.dailyQuotaGb)`""
    }

    $TagNames = $Obj.Tags | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    If($TagNames) {
        $Global:TFResources += $NL + "  tags     = {"

        ForEach($TagName In $TagNames) {
            $Global:TFResources += "    $TagName = `"$($Obj.Tags.$TagName)`""
        }

        $Global:TFResources += "  }"
    }

    $Global:TFResources += "}" + $NL

    $Global:TFImport += "terraform import azurerm_log_analytics_workspace.lwks_$($Obj.Name) $($Obj.Id)"    
}

#Main loop
ForEach ($Resource In $Resources) {
    $Type = $Resource.Type

    Switch ($Type) {
        'microsoft.operationalinsights/workspaces' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                              = $Resource.Id
                Name                            = $Resource.Name
                Location                        = $Resource.location
                ResourceGroup                   = [PSCustomObject]@{
                    Id          	            = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name                        = $Resource.resourceGroup
                }
                SkuName                         = $Properties.sku.name
                RetentionInDays                 = $Properties.retentionInDays
                PublicNetworkAccessForIngestion = $Properties.publicNetworkAccessForIngestion
                PublicNetworkAccessForQuery     = $Properties.publicNetworkAccessForQuery
                CustomerId                      = $Properties.customerId
                Features                        = $Properties.features
                Source                          = $Properties.source
                WorkspaceCapping                = $Properties.workspaceCapping
                Tags                            = $Resource.tags 
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllLogWks.Contains($Obj.Id)) { $AllLogWks.Add($Obj.Id, $Obj) }
        }

        'microsoft.keyvault/vaults' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                           = $Resource.Id
                Name                         = $Resource.Name
                Location                     = $Resource.location
                ResourceGroup                = [PSCustomObject]@{
                    Id          	         = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name                     = $Resource.resourceGroup
                }
                EnableRbacAuthorization      = $Properties.enableRbacAuthorization
                EnableSoftDelete             = $Properties.enableSoftDelete
                EnabledForDeployment         = $Properties.enabledForDeployment
                EnabledForDiskEncryption     = $Properties.enabledForDiskEncryption
                EnabledForTemplateDeployment = $Properties.enabledForTemplateDeployment
                SkuName                      = $Properties.sku.name
                SkuFamily                    = $Properties.sku.family
                SoftDeleteRetentionInDays    = $Properties.softDeleteRetentionInDays
                VaultUri                     = $Properties.vaultUri
                TenantID                     = $Resource.tenantId
                AccessPolicies               = $Properties.accessPolicies
                Tags                         = $Resource.tags               
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllKeyVaults.Contains($Obj.Id)) { $AllKeyVaults.Add($Obj.Id, $Obj) }
        }

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
                Tags                      = $Resource.tags
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllAVSets.Contains($Obj.Id)) { $AllAVSets.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/routetables' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                         = $Resource.Id
                Name                       = $Resource.Name
                Location                   = $Resource.location
                ResourceGroup              = [PSCustomObject]@{
                    Id          	       = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name                   = $Resource.resourceGroup
                }
                DisableBgpRoutePropagation = $Properties.disableBgpRoutePropagation
                Routes                     = $Properties.routes
                SubnetAssociation          = @()
                Tags                       = $Resource.tags
            }

            ForEach($Subnet In $Properties.subnets) {
                $Split = $Subnet.id -split '/'
                $SubnetName = "$($Split[$Split.Count - 3])_$($Split[$Split.Count - 1])"

                $Obj.SubnetAssociation += [PSCustomObject]@{
                    SubnetId       = $Subnet.id
                    RouteTableId   = $Resource.id
                    SubnetName     = $SubnetName
                    RouteTableName = $Resource.Name
                }
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllRouteTables.Contains($Obj.Id)) { $AllRouteTables.Add($Obj.Id, $Obj) }
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
                Tags                   = $Resource.tags
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllPIPs.Contains($Obj.Id)) { $AllPIPs.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/connections' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                             = $Resource.Id
                Name                           = $Resource.Name
                Location                       = $Resource.location
                ResourceGroup                  = [PSCustomObject]@{
                    Id          	           = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name                       = $Resource.resourceGroup
                }
                Mode                           = $Properties.connectionMode
                Protocol                       = $Properties.connectionProtocol
                Type                           = $Properties.connectionType
                DpdTimeoutSeconds              = $Properties.dpdTimeoutSeconds
                EnableBgp                      = $Properties.enableBgp
                ExpressRouteGatewayBypass      = $Properties.expressRouteGatewayBypass
                IpsecPolicies                  = $Properties.ipsecPolicies
                LocalNetworkGatewayId          = $Properties.localNetworkGateway2.Id
                VirtualNetworkGatewayId        = $Properties.virtualNetworkGateway1.Id
                RoutingWeight                  = $Properties.routingWeight
                SharedKey                      = $Properties.sharedKey
                TrafficSelectorPolicies        = $Properties.trafficSelectorPolicies
                UseLocalAzureIpAddress         = $Properties.useLocalAzureIpAddress
                UsePolicyBasedTrafficSelectors = $Properties.usePolicyBasedTrafficSelectors
                Tags                           = $Resource.tags
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllGWConnections.Contains($Obj.Id)) { $AllGWConnections.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/localnetworkgateways' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                     = $Resource.Id
                Name                   = $Resource.Name
                Location               = $Resource.location
                ResourceGroup          = [PSCustomObject]@{
                    Id          	   = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name               = $Resource.resourceGroup
                }
                BgpSettings            = $Properties.bgpSettings
                GatewayIPAddress       = $Properties.gatewayIpAddress
                AddressPrefixes        = $Properties.localNetworkAddressSpace.addressPrefixes
                Tags                   = $Resource.tags
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllLocalGWs.Contains($Obj.Id)) { $AllLocalGWs.Add($Obj.Id, $Obj) }
        }

        'microsoft.network/virtualnetworkgateways' {
            $Properties = $Resource.Properties
            $IPConfigs = $Properties.ipConfigurations

            $Obj = [PSCustomObject]@{
                Id                     = $Resource.Id
                Name                   = $Resource.Name
                Location               = $Resource.location
                ResourceGroup          = [PSCustomObject]@{
                    Id          	   = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name               = $Resource.resourceGroup
                }
                Type                   = $Properties.gatewayType
                VpnType                = $Properties.vpnType
                ActiveActive           = $Properties.activeActive
                EnableBGP              = $Properties.enableBgp
                Sku                    = $Properties.sku.name
                VPNGatewayGeneration   = $Properties.vpnGatewayGeneration
                BgpSettings            = $Properties.bgpSettings
                ClientConfiguration    = $Properties.vpnClientConfiguration
                VnetPeeringsIDs        = $Properties.remoteVirtualNetworkPeerings.id
                Tags                   = $Resource.tags                
                IPConfigs              = @()
            }

            ForEach ($IPConfig In $IPConfigs) {
                $IPProperties = $IPConfig.Properties

                $Obj.IPConfigs += [PSCustomObject]@{
                    Name                      = $IPConfig.Name
                    PrivateIPAllocationMethod = $IPProperties.privateIPAllocationMethod
                    PublicIPId                = $IPProperties.publicIPAddress.id
                    SubnetId                  = $IPProperties.subnet.id
                }
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllGWs.Contains($Obj.Id)) { $AllGWs.Add($Obj.Id, $Obj) }
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

            ForEach ($Peering In $Peerings) {
                $PeeringProperties = $Peering.properties

                $Obj.Peerings += [PSCustomObject]@{
                    Id                        = $Peering.id
                    Name                      = $Peering.name
                    ResourceGroup = [PSCustomObject]@{
                        Id        = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Peering.resourceGroup)"
                        Name      = $Peering.resourceGroup
                    }
                    SubscriptionId            = $Resource.subscriptionId                    
                    AllowForwardedTraffic     = $PeeringProperties.allowForwardedTraffic
                    AllowGatewayTransit       = $PeeringProperties.allowGatewayTransit
                    AllowVirtualNetworkAccess = $PeeringProperties.allowVirtualNetworkAccess
                    DoNotVerifyRemoteGateways = $PeeringProperties.doNotVerifyRemoteGateways
                    RemoteAddressPrefixes     = $PeeringProperties.remoteAddressSpace.addressPrefixes
                    RemoteVirtualNetworkIds   = $PeeringProperties.remoteVirtualNetwork.id
                    RouteServiceVips          = $PeeringProperties.routeServiceVips
                    UseRemoteGateways         = $PeeringProperties.useRemoteGateways
                    RemoteVirtualNetwork      = $PeeringProperties.remoteVirtualNetwork
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
                Id                    = $Resource.Id
                Name                  = $Resource.Name
                Location              = $Resource.location
                ResourceGroup         = [PSCustomObject]@{
                    Id                = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name              = $Resource.resourceGroup
                }
                Tags                  = $Resource.tags
                AcceleratedNetworking = $Properties.enableAcceleratedNetworking
                IPForwarding          = $Properties.enableIPForwarding
                IPConfigs             = @()
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

        'microsoft.network/networksecuritygroups' {
            $Properties = $Resource.Properties

            $Obj = [PSCustomObject]@{
                Id                   = $Resource.Id
                Name                 = $Resource.Name
                Location             = $Resource.location
                ResourceGroup        = [PSCustomObject]@{
                    Id          	 = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name             = $Resource.resourceGroup
                }
                DefaultSecurityRules = $Properties.defaultSecurityRules
                SecurityRules        = $Properties.securityRules
                NicAssociation       = @()
                SubnetAssociation    = @()
                Tags                 = $Resource.tags
            }

            ForEach($Nic In $Properties.networkInterfaces) {
                $Split = $Nic.id -split '/'
                $NicName = $($Split[$Split.Count - 1])

                $Obj.NicAssociation += [PSCustomObject]@{
                    NicId   = $Nic.id
                    NSGId   = $Resource.id
                    NicName = $NicName
                    NSGName = $Resource.Name
                }
            }

            ForEach($Subnet In $Properties.subnets) {
                $Split = $Subnet.id -split '/'
                $SubnetName = "$($Split[$Split.Count - 3])_$($Split[$Split.Count - 1])"

                $Obj.SubnetAssociation += [PSCustomObject]@{
                    SubnetId   = $Subnet.id
                    NSGId      = $Resource.id
                    SubnetName = $SubnetName
                    NSGName    = $Resource.Name
                }
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllNSGs.Contains($Obj.Id)) { $AllNSGs.Add($Obj.Id, $Obj) }
        }

        'microsoft.compute/virtualmachines' {
            $Properties = $Resource.Properties
            $Nics = $Properties.networkProfile.networkinterfaces
            $StorageProfile = $Properties.storageProfile
            $DiagProfile = $Properties.diagnosticsProfile
            $OsProfile = $Properties.osProfile
            $ImageReference = $StorageProfile.imagereference
            $OsDiskInfo = $StorageProfile.osDisk
            $DiskResources = $Resources | Where-Object {$_.Type -eq 'microsoft.compute/disks'}
            $VMDisks = $DiskResources | Where-Object {$_.managedBy -eq $Resource.Id}

            If ($OsProfile.windowsConfiguration) { $OperatingSystem = "Windows" } 
            If ($OsProfile.linuxConfiguration) { $OperatingSystem = "Linux" }

            $Obj = [PSCustomObject]@{
                Id                = $Resource.Id
                Name              = $Resource.Name
                Location          = $Resource.location
                ResourceGroup     = [PSCustomObject]@{
                    Id            = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                    Name          = $Resource.resourceGroup
                }
                OperatingSystem   = $OperatingSystem
                OsProfile         = $OsProfile
                Size              = $Properties.hardwareProfile.vmSize
                Nics              = @()
                Disks             = @()
                AdminUsername     = $OsProfile.adminUsername
                Publisher         = $ImageReference.publisher
                Offer             = $ImageReference.offer
                Sku               = $ImageReference.sku
                Version           = $ImageReference.version
                LicenseType       = $Properties.licenseType
                BootDiagnostics   = $DiagProfile.bootDiagnostics
                AvailabilitySetId = $Properties.availabilitySet.Id
                OsDiskInfo        = $OSDiskInfo
                Tags              = $Resource.tags
                Priority          = $Properties.priority
                EvictionPolicy    = $Properties.evictionPolicy
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
                    Tags               = $VMDisk.tags
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
                    Id                 = $Resource.Id
                    Name               = $Resource.Name
                    Location           = $Resource.location
                    ResourceGroup      = [PSCustomObject]@{
                        Id             = "/subscriptions/$($Resource.subscriptionId)/resourceGroups/$($Resource.resourceGroup)"
                        Name           = $Resource.resourceGroup
                    }
                    VMId               = $Resource.managedBy
                    SizeGB             = $Resource.properties.diskSizeGB
                    State              = $Resource.properties.diskState
                    OsType             = $Resource.properties.osType
                    StorageAccountType = $Resource.sku.name
                    CreateOption       = $Resource.properties.creationData.createOption
                    Tags               = $Resource.tags                           
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

$AllRGs.Values           | ForEach-Object { GetTFResourceGroup($_) }
$AllSTGs.Values          | ForEach-Object { GetTFStorageAccount($_) }
$AllAVSets.Values        | ForEach-Object { GetTFAvailSet($_) }
$AllGWConnections.Values | ForEach-Object { GetTFGatewayConnection($_) }
$AllLocalGWs.Values      | ForEach-Object { GetTFLocalGateway($_) }
$AllGWs.Values           | ForEach-Object { GetTFVirtualGateway($_) }
$AllVNets.Values         | ForEach-Object { GetTFVirtualNetwork($_) }
$AllVNets.Values.Subnets | ForEach-Object { GetTFSubnet($_) }
$AllPIPs.Values          | ForEach-Object { GetTFPublicIP($_) }
$AllNICs.Values          | ForEach-Object { GetTFNetInterface($_) }
$AllNSGs.Values          | ForEach-Object { GetTFNetSecurityGroup($_) }
$AllDisks.Values         | ForEach-Object { GetTFManagedDisk($_) }
$AllRouteTables.Values   | ForEach-Object { GetTFRouteTable($_) }
$AllVMs.Values           | Where-Object {$_.OperatingSystem -eq "Windows"} | ForEach-Object { GetTFWindowsVM($_) }
$AllVMs.Values           | Where-Object {$_.OperatingSystem -eq "Linux"} | ForEach-Object { GetTFLinuxVM($_) }
$AllKeyVaults.Values     | ForEach-Object { GetTFKeyVault($_) }
$AllLogWks.Values        | ForEach-Object { GetTFLogWorkspace($_) }
$AllDisks.Values         | Where-Object {$_.VMId} | Sort-Object properties.storageprofile.datadisks.lun | ForEach-Object { GetTFDataDiskAttachment($_) }

$null = New-Item -Name $TFResourcesFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFResources -Join $NL) -Force

Write-Host "[$(Get-Date)] Indenting files..."
$null = terraform fmt $TFDirectory

Write-Host "[$(Get-Date)] Generating import file..."
$null = New-Item -Name $TFImportFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFImport -Join $NL) -Force