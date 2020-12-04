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

$Resources = az graph query -q  "resources | where subscriptionId == '$SubscriptionID' | order by id asc" --output json --only-show-errors | ConvertFrom-Json

$TFDirectory = "terraform"
$TFMainFile = "main.tf"
$TFResourcesFile = "resources.tf"
$AllRGs = @{ }
$AllVMs = @{ }
$AllSTGs = @{ }
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
    "$($SP2)resource_group_name      = `"$($Obj.ResourceGroup.Name)`"" + $NL +
    "$($SP2)location                 = `"$($Obj.Location)`"" + $NL +
    "$($SP2)account_tier             = `"$($Obj.AccountTier)`"" + $NL +
    "$($SP2)account_replication_type = `"$($Obj.AccountReplicationType)`"" + $NL +
    "}" + $NL

    $Global:TFImport += "terraform import azurerm_storage_account.stg_$($Obj.Name) $($Obj.Id)"  
}

Function GetTFWindowsVM($Obj) {
    $Global:TFResources += "resource `"azurerm_windows_virtual_machine`" `"vm_$($Obj.Name)`" {" + $NL +
    "$($SP2)name                = `"$($Obj.Name)`"" + $NL +
    "$($SP2)resource_group_name = `"$($Obj.ResourceGroup.Name)`"" + $NL +
    "$($SP2)location            = `"$($Obj.Location)`"" + $NL +
    "$($SP2)size                = `"$($Obj.Size)`"" + $NL +
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
                AccountTier            = ($Resource.sku.name -split "_")[0]
                AccountReplicationType = ($Resource.sku.name -split "_")[1]     
            }

            If (-Not $AllRGs.Contains($Obj.ResourceGroup.Id)) { $AllRGs.Add($Obj.ResourceGroup.Id, $Obj.ResourceGroup) }
            If (-Not $AllSTGs.Contains($Obj.Id)) { $AllSTGs.Add($Obj.Id, $Obj) }
        }

        'microsoft.compute/virtualmachines' {
            $Properties = $Resource.Properties

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
$AllVMs.Values | ForEach-Object { GetTFWindowsVM($_) }

$null = New-Item -Name $TFResourcesFile -Path (Join-Path (Get-Location).Path $TFDirectory) -Type File -Value ($TFResources -Join $NL) -Force

Write-Host "[$(Get-Date)] Indenting files..."
$null = terraform fmt $TFDirectory