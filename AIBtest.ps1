#https://github.com/danielsollondon/azvmimagebuilder/tree/master/solutions/14_Building_Images_WVD


#Step 1: Set up environment and variables
# Step 1: Import module
Import-Module Az.Accounts

# Step 2: get existing context
$currentAzContext = Get-AzContext

# destination image resource group
$imageResourceGroup="wvdImageDemoRgEurope"

# location (see possible locations in main docs)
$location="westeurope"

# your subscription, this will get your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

# image template name
$imageTemplateName="wvd11ImageTemplateCIS2"

# distribution properties object name (runOutput), i.e. this gives you the properties of the managed image on completion
$runOutputName="sigOutput"

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
$publisher = "Pink"

# create gallery. This can take a few minutes.
New-AzGallery -GalleryName $sigGalleryName -ResourceGroupName $imageResourceGroup -Location $location


# create gallery definition
New-AzGalleryImageDefinition -GalleryName $sigGalleryName -ResourceGroupName $imageResourceGroup -Location $location -Name $imageDefName -OsState generalized -OsType Windows -Publisher $publisher -Offer 'Windows' -Sku '11wvd' -HyperVGeneration 'V2'

#Download template and configure and make your changes to the template
$templateUrl="https://raw.githubusercontent.com/zapocalypse/CIS/main/windows11avd.json"
$templateFilePath = "armTemplateWVD.json"

Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<rgName>',$imageResourceGroup) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>',$runOutputName) | Set-Content -Path $templateFilePath

((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>',$imageDefName) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>',$sigGalleryName) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<region1>',$location) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>',$identityNameResourceId) | Set-Content -Path $templateFilePath

#replace template values
((Get-Content -path $templateFilePath -Raw) -replace "windows-10","windows-11") | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace "windows10","windows11") | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace "20h1-ent","win11-22h2-avd") | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace "wvd10","wvd11") | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace "Standard_D2_v2","Standard_B2ms") | Set-Content -Path $templateFilePath


#Submit the template
New-AzResourceGroupDeployment -ResourceGroupName $imageResourceGroup -TemplateFile $templateFilePath -api-version "2022-02-14" -imageTemplateName $imageTemplateName -svclocation $location

#Build the image
Start-AzImageBuilderTemplate -Name $imageTemplateName -ResourceGroupName $imageResourceGroup  -NoWait



Get-AzVMImagePublisher -Location $location | Select PublisherName

$pubName="MicrosoftWindowsDesktop"
Get-AzVMImageOffer -Location $location -PublisherName $pubName | Select Offer

$offerName="windows-11"
Get-AzVMImageSku -Location $location -PublisherName $pubName -Offer $offerName | Select Skus

Get-AzVMImageSku -Location germanywestcentral -PublisherName MicrosoftWindowsDesktop -Offer windows-11 | Select Skus

#The provided SIG: /subscriptions/1b4cc42d-e82b-4930-86e3-1651c242ba05/resourceGroups/wvdImageDemoRg2/providers/Microsoft.Compute/galleries/AIBGallery2/images/AIBtest, has a different Hyper-V Generation: V1, than source image: V2. (Code:ValidationFailed)
#CorrelationId: 8a6d22c6-ff42-4823-9e2b-23a1affb3e60

#For image build failures, you can get the error from the 'lastrunstatus', and then review the details in the customization.log.

az resource show  --resource-group $imageResourceGroup  --resource-type Microsoft.VirtualMachineImages/imageTemplates -n $imageTemplateName

Register-AzResourceProvider -ProviderNamespace Microsoft.Network