# AzureToTerraformConverter
Convert Azure resources to Terraform files

.\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"

PS C:\> **.\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"**
[12/15/2020 17:21:48] Checking tool dependencies...
[12/15/2020 17:22:01] Finding resources in subscription <my_subscription_ID>...
[12/15/2020 17:22:05] Generating terraform files...
[12/15/2020 17:22:05] Indenting files...
[12/15/2020 17:22:12] Generating import file...
PS C:\>

PS C:\> cd .\terraform\
PS C:\terraform> dir

    Directory: C:\terraform

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/15/2020   5:22 PM             63 main.tf
-a----        12/15/2020   5:22 PM           3576 resources.tf
-a----        12/15/2020   5:22 PM           2211 terraform_import.cmd

PS C:\terraform>

PS C:\terraform> **terraform init**

Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/azurerm versions matching "~> 2.21"...
- Installing hashicorp/azurerm v2.40.0...
- Installed hashicorp/azurerm v2.40.0 (signed by HashiCorp)

***Terraform has been successfully initialized!***

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

PS C:\terraform> **terraform validate**
***Success! The configuration is valid.***

PS C:\terraform> **.\terraform_import.cmd**

...

C:\terraform> ***terraform import azurerm_resource_group.rg_containers /subscriptions/<my_subscription_ID>/resourceGroups/containers***
azurerm_resource_group.rg_containers: Importing from ID "/subscriptions/<my_subscription_ID>/resourceGroups/containers"...
azurerm_resource_group.rg_containers: Import prepared!
  Prepared azurerm_resource_group for import
azurerm_resource_group.rg_containers: Refreshing state... [id=/subscriptions/<my_subscription_ID>/resourceGroups/containers]

***Import successful!***

The resources that were imported are shown above. These resources are now in
your Terraform state and will henceforth be managed by Terraform.

PS C:\terraform> ***terraform plan***
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.

azurerm_resource_group.rg_containers: Refreshing state... [id=/subscriptions/<my_subscription_ID>/resourceGroups/containers]

...

------------------------------------------------------------------------

***No changes. Infrastructure is up-to-date.***

This means that Terraform did not detect any differences between your
configuration and real physical resources that exist. As a result, no
actions need to be performed.

PS C:\terraform> ***Get-Content .\main.tf***
provider "azurerm" {
  version = "~> 2.21"
  features {}
}

PS C:\terraform> ***Get-Content .\resources.tf***
resource "azurerm_resource_group" "rg_containers" {
  name     = "containers"
  location = "westus2"
}

resource "azurerm_resource_group" "rg_mfrg" {
  name     = "mfrg"
  location = "eastus"

  tags = {
    CostCenter = "10203040"
    Dept       = "IT"
    Owner      = "Marcus"
  }
}

resource "azurerm_storage_account" "stg_account_name" {
  name                     = "<storage_account_name>"
  resource_group_name      = azurerm_resource_group.rg_mfrg.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "LRS"
  allow_blob_public_access = true
  min_tls_version          = "TLS1_2"

  tags = {
    Delete = "123"
    Env    = "Test"
  }
}

resource "azurerm_virtual_network" "vnet_main-vnet" {
  name                = "main-vnet"
  resource_group_name = azurerm_resource_group.rg_mfrg.name
  location            = "eastus"
  address_space       = ["10.8.0.0/16"]
  dns_servers         = ["10.10.13.101", "10.7.0.4"]

  tags = {
    blah        = "123"
    Environment = "Prod"
  }
}

resource "azurerm_subnet" "subnet_GatewaySubnet" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.rg_mfrg.name
  virtual_network_name = azurerm_virtual_network.vnet_main-vnet.name
  address_prefixes     = ["10.8.200.0/24"]
}

resource "azurerm_subnet" "subnet_hybridsubnet" {
  name                 = "hybridsubnet"
  resource_group_name  = azurerm_resource_group.rg_mfrg.name
  virtual_network_name = azurerm_virtual_network.vnet_main-vnet.name
  address_prefixes     = ["10.8.2.0/24"]
}

resource "azurerm_subnet" "subnet_default" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.rg_mfrg.name
  virtual_network_name = azurerm_virtual_network.vnet_main-vnet.name
  address_prefixes     = ["10.8.0.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "subnet_AzureBastionSubnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg_mfrg.name
  virtual_network_name = azurerm_virtual_network.vnet_main-vnet.name
  address_prefixes     = ["10.8.3.0/24"]
}

resource "azurerm_subnet" "subnet_corp-subnet" {
  name                 = "corp-subnet"
  resource_group_name  = azurerm_resource_group.rg_mfrg.name
  virtual_network_name = azurerm_virtual_network.vnet_main-vnet.name
  address_prefixes     = ["10.8.1.0/24"]
  service_endpoints    = ["Microsoft.Storage", "Microsoft.KeyVault"]
}

resource "azurerm_public_ip" "pip_azgwpublicip" {
  name                    = "azgwpublicip"
  resource_group_name     = azurerm_resource_group.rg_mfrg.name
  location                = "eastus"
  allocation_method       = "Dynamic"
  sku                     = "Basic"
  ip_version              = "IPv4"
  idle_timeout_in_minutes = "4"
}

resource "azurerm_managed_disk" "disk_notuseddisk_0" {
  name                 = "notuseddisk_0"
  location             = "westus2"
  resource_group_name  = azurerm_resource_group.rg_containers.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "32"
}

resource "azurerm_managed_disk" "disk_notuseddisk_1" {
  name                 = "notuseddisk_1"
  location             = "brazilsouth"
  resource_group_name  = azurerm_resource_group.rg_containers.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "32"
}

PS C:\terraform>