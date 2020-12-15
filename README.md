# AzureToTerraformConverter
Convert Azure resources to Terraform files

***Use this as a starting point for managing Infrastructure as Code,
After using it, make sure to use variables, modules, etc.
Always follow best practices. Use at your own risk. Test it in lab first.
***

.\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"

PS C:\> **.\Convert_Az2TF.ps1 -SubscriptionID "<my_subscription_ID>"**
```
[12/15/2020 17:21:48] Checking tool dependencies...
[12/15/2020 17:22:01] Finding resources in subscription <my_subscription_ID>...
[12/15/2020 17:22:05] Generating terraform files...
[12/15/2020 17:22:05] Indenting files...
[12/15/2020 17:22:12] Generating import file...
```
PS C:\>

PS C:\> cd .\terraform\
PS C:\terraform> dir
```
    Directory: C:\terraform

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/15/2020   5:22 PM             63 main.tf
-a----        12/15/2020   5:22 PM           3576 resources.tf
-a----        12/15/2020   5:22 PM           2211 terraform_import.cmd
```
PS C:\terraform>

PS C:\terraform> **terraform init**
```
Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/azurerm versions matching "~> 2.21"...
- Installing hashicorp/azurerm v2.40.0...
- Installed hashicorp/azurerm v2.40.0 (signed by HashiCorp)

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```
PS C:\terraform> **terraform validate**
```
Success! The configuration is valid.
```
PS C:\terraform> **.\terraform_import.cmd**
```
...

C:\terraform> terraform import azurerm_resource_group.rg_containers /subscriptions/<my_subscription_ID>/resourceGroups/containers

azurerm_resource_group.rg_containers: Importing from ID "/subscriptions/<my_subscription_ID>/resourceGroups/containers"...
azurerm_resource_group.rg_containers: Import prepared!
  Prepared azurerm_resource_group for import
azurerm_resource_group.rg_containers: Refreshing state... [id=/subscriptions/<my_subscription_ID>/resourceGroups/containers]

Import successful!

The resources that were imported are shown above. These resources are now in
your Terraform state and will henceforth be managed by Terraform.
```
PS C:\terraform> ***terraform plan***
```
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.

azurerm_resource_group.rg_containers: Refreshing state... [id=/subscriptions/<my_subscription_ID>/resourceGroups/containers]

...

------------------------------------------------------------------------

No changes. Infrastructure is up-to-date.

This means that Terraform did not detect any differences between your
configuration and real physical resources that exist. As a result, no
actions need to be performed.
```
PS C:\terraform> ***Get-Content .\main.tf***
```
provider "azurerm" {
  version = "~> 2.21"
  features {}
}
```
PS C:\terraform> ***Get-Content .\resources.tf***
```
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
    Owner      = "Contoso"
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
```

PS C:\terraform>

PS C:\terraform> ***Get-Content .\resources.tf***
```
resource "azurerm_resource_group" "rg_tfstate" {
  name     = "tfstate"
  location = "eastus2"
}

resource "azurerm_resource_group" "rg_wvdnewrg" {
  name     = "wvdnewrg"
  location = "eastus"
}

resource "azurerm_resource_group" "rg_mflabs" {
  name     = "mflabs"
  location = "eastus"
}

resource "azurerm_storage_account" "stg_acc_name1" {
  name                     = "stg_acc_name1"
  resource_group_name      = azurerm_resource_group.rg_tfstate.name
  location                 = "eastus2"
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "LRS"
}

resource "azurerm_storage_account" "stg_acc_name2" {
  name                     = "stg_acc_name2"
  resource_group_name      = azurerm_resource_group.rg_mflabs.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_kind             = "Storage"
  account_replication_type = "LRS"
}

resource "azurerm_availability_set" "avset_wvd-vm-availabilitySet-eastus" {
  name                         = "wvd-vm-availabilitySet-eastus"
  resource_group_name          = azurerm_resource_group.rg_wvdnewrg.name
  location                     = "eastus"
  managed                      = true
  platform_fault_domain_count  = "2"
  platform_update_domain_count = "5"
}

resource "azurerm_availability_set" "avset_wvdvmnew-availabilitySet-eastus" {
  name                         = "wvdvmnew-availabilitySet-eastus"
  resource_group_name          = azurerm_resource_group.rg_wvdnewrg.name
  location                     = "eastus"
  managed                      = true
  platform_fault_domain_count  = "2"
  platform_update_domain_count = "5"
}

resource "azurerm_virtual_network" "vnet_mflabs-vnet" {
  name                = "mflabs-vnet"
  resource_group_name = azurerm_resource_group.rg_mflabs.name
  location            = "eastus"
  address_space       = ["10.7.0.0/16"]
  dns_servers         = ["10.10.13.101", "10.7.0.4"]
}

resource "azurerm_subnet" "subnet_mflabs-azsubnet" {
  name                 = "mflabs-azsubnet"
  resource_group_name  = azurerm_resource_group.rg_mflabs.name
  virtual_network_name = azurerm_virtual_network.vnet_mflabs-vnet.name
  address_prefixes     = ["10.7.0.0/24"]
}

resource "azurerm_public_ip" "pip_AZDC1-ip" {
  name                    = "AZDC1-ip"
  resource_group_name     = azurerm_resource_group.rg_mflabs.name
  location                = "eastus"
  allocation_method       = "Dynamic"
  sku                     = "Basic"
  ip_version              = "IPv4"
  idle_timeout_in_minutes = "4"
}

resource "azurerm_public_ip" "pip_AZCS1-ip" {
  name                    = "AZCS1-ip"
  resource_group_name     = azurerm_resource_group.rg_mflabs.name
  location                = "eastus"
  allocation_method       = "Dynamic"
  sku                     = "Basic"
  ip_version              = "IPv4"
  idle_timeout_in_minutes = "4"
  domain_name_label       = "<domain_name_label>"
}

resource "azurerm_network_interface" "nic_azdc1801" {
  name                = "azdc1801"
  resource_group_name = azurerm_resource_group.rg_mflabs.name
  location            = "eastus"

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.subnet_mflabs-azsubnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip_AZDC1-ip.id
  }

  ip_configuration {
    name                          = "ipconfig2"
    subnet_id                     = azurerm_subnet.subnet_mflabs-azsubnet.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = {
    blah = "test"
    yep  = "5"
  }
}

resource "azurerm_network_interface" "nic_wvd-vm-0-nic" {
  name                = "wvd-vm-0-nic"
  resource_group_name = azurerm_resource_group.rg_wvdnewrg.name
  location            = "eastus"

  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.subnet_mflabs-azsubnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface" "nic_wvdvmnew-0-nic" {
  name                = "wvdvmnew-0-nic"
  resource_group_name = azurerm_resource_group.rg_wvdnewrg.name
  location            = "eastus"

  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.subnet_mflabs-azsubnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface" "nic_azcs1490" {
  name                = "azcs1490"
  resource_group_name = azurerm_resource_group.rg_mflabs.name
  location            = "eastus"

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.subnet_mflabs-azsubnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip_AZCS1-ip.id
  }
}

resource "azurerm_managed_disk" "disk_AZDC1_DataDisk_0" {
  name                 = "AZDC1_DataDisk_0"
  location             = "eastus"
  resource_group_name  = azurerm_resource_group.rg_mflabs.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "128"
}

resource "azurerm_windows_virtual_machine" "vm_AZDC1" {
  name                = "AZDC1"
  resource_group_name = azurerm_resource_group.rg_mflabs.name
  location            = "eastus"
  size                = "Standard_B2s"
  admin_username      = "<user>"
  admin_password      = "<passwd>"
  license_type        = "Windows_Server"

  boot_diagnostics {
    storage_account_uri = "https://<storage_account_name>.blob.core.windows.net/"
  }

  network_interface_ids = [
    azurerm_network_interface.nic_azdc1801.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = "127"
    name                 = "AZDC1_OsDisk_1_5498a2a2073341c9b67abaa47673899d"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2012-R2-Datacenter"
    version   = "latest"
  }
}

resource "azurerm_windows_virtual_machine" "vm_AZCS1" {
  name                = "AZCS1"
  resource_group_name = azurerm_resource_group.rg_mflabs.name
  location            = "eastus"
  size                = "Standard_B2s"
  admin_username      = "<user>"
  admin_password      = "<passwd>"
  license_type        = "Windows_Server"

  boot_diagnostics {
    storage_account_uri = "https://<storage_account_name>.blob.core.windows.net/"
  }

  network_interface_ids = [
    azurerm_network_interface.nic_azcs1490.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = "127"
    name                 = "AZCS1_OsDisk_1_14b0d6fd0a2940ccab5b04c5f9560dd8"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }
}

resource "azurerm_windows_virtual_machine" "vm_wvd-vm-0" {
  name                = "wvd-vm-0"
  resource_group_name = azurerm_resource_group.rg_wvdnewrg.name
  location            = "eastus"
  size                = "Standard_D2s_v3"
  admin_username      = "<user>"
  admin_password      = "<passwd>"
  license_type        = "Windows_Client"
  availability_set_id = azurerm_availability_set.avset_wvd-vm-availabilitySet-eastus.id

  network_interface_ids = [
    azurerm_network_interface.nic_wvd-vm-0-nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = "127"
    name                 = "wvd-vm-0_OsDisk_1_76c703cc6c544127b2f68cc9775eb018"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "office-365"
    sku       = "20h1-evd-o365pp"
    version   = "latest"
  }
}

resource "azurerm_virtual_machine_data_disk_attachment" "disk_att_AZDC1_DataDisk_0" {
  managed_disk_id    = azurerm_managed_disk.disk_AZDC1_DataDisk_0.id
  virtual_machine_id = azurerm_windows_virtual_machine.vm_AZDC1.id
  lun                = 0
  caching            = "None"
}
```
PS C:\terraform>