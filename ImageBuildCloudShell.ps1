#This configuration is based on the documentation of the githubpage:
#https://github.com/danielsollondon/azvmimagebuilder/tree/master/solutions/14_Building_Images_WVD

# Register for Azure Image Builder Feature
Register-AzProviderFeature -FeatureName VirtualMachineTemplatePreview -ProviderNamespace Microsoft.VirtualMachineImages

Get-AzProviderFeature -FeatureName VirtualMachineTemplatePreview -ProviderNamespace Microsoft.VirtualMachineImages
# wait until RegistrationState is set to 'Registered'

#Register required providers
Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages
Register-AzResourceProvider -ProviderNamespace Microsoft.Storage
Register-AzResourceProvider -ProviderNamespace Microsoft.Compute
Register-AzResourceProvider -ProviderNamespace Microsoft.KeyVault
Register-AzResourceProvider -ProviderNamespace Microsoft.Network


#Step 1: Set up environment and variables
# Import module
Import-Module Az.Accounts

# get existing context
$currentAzContext = Get-AzContext

# destination image resource group
$imageResourceGroup="wvd11rg"

# location (see possible locations in main docs)
$location="eastus"

# your subscription, this will get your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

# image template name
$imageTemplateName="wvd11"

# distribution properties object name (runOutput), i.e. this gives you the properties of the managed image on completion
$runOutputName="computeGalleryOutput"

# create resource group
New-AzResourceGroup -Name $imageResourceGroup -Location $location


#Step 2 : Permissions, create user identity and role for AIB
# setup role def names, these need to be unique
$timeInt=$(get-date -UFormat "%s")
$imageRoleDefName="Azure Image Builder Image Def"+$timeInt
$identityName="AIBGalleryid"

## Add AZ PS modules to support AzUserAssignedIdentity and Az AIB
'Az.ImageBuilder', 'Az.ManagedServiceIdentity' | ForEach-Object {Install-Module -Name $_ -AllowPrerelease}

# create identity
New-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName -Location $location

#Wait until the managed identity is created before continuing. This can take a few minutes.

$identityNameResourceId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).Id
$identityNamePrincipalId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).PrincipalId

#Assign permissions for identity to distribute images
$aibRoleImageCreationUrl="https://raw.githubusercontent.com/danielsollondon/azvmimagebuilder/master/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
$aibRoleImageCreationPath = "aibRoleImageCreation.json"

# download config
Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $imageResourceGroup) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

# create role definition
New-AzRoleDefinition -InputFile  ./aibRoleImageCreation.json

#wait until the role definition and its persmission are created before continuing. This can take a few minutes.

# grant role definition to image builder service principal
New-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $imageRoleDefName -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"


#Step 3 : Create the Shared Image Gallery
$sigGalleryName= "My_Gallery"
$imageDefName ="Virtual_Desktop"
$publisher = "pub"

# create gallery. This can take a few minutes. 
New-AzGallery -GalleryName $sigGalleryName -ResourceGroupName $imageResourceGroup -Location $location


# create gallery definition
New-AzGalleryImageDefinition -GalleryName $sigGalleryName -ResourceGroupName $imageResourceGroup -Location $location -Name $imageDefName -OsState generalized -OsType Windows -Publisher $publisher -Offer 'Windows' -Sku '11wvd' -HyperVGeneration 'V2'

#Download template and configure and make your changes to the template
$templateUrl="https://raw.githubusercontent.com/zapocalypse/CIS/main/windows11_wvd_cis_hardening.json"
$templateFilePath = "windows11_wvd_cis_hardening.json"

Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing
((Get-Content -path $templateFilePath -Raw) -replace '<subscription_id>',$subscriptionID) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<GalleryName>',$sigGalleryName) | Set-Content -Path $templateFilePath


 #Submit the template
New-AzResourceGroupDeployment -ResourceGroupName $imageResourceGroup -TemplateFile $templateFilePath -api-version "2022-02-14" -imageTemplateName $imageTemplateName -svclocation $location

#Build the image
Start-AzImageBuilderTemplate -Name $imageTemplateName -ResourceGroupName $imageResourceGroup  -NoWait
