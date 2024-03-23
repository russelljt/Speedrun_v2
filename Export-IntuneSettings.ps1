
$TenantID = "theartoffoolishness.com" 
$AppID = "14d82eec-204b-4c2f-b7e8-296a70dab67e" # Default Microsoft Graph PowerShell Enterprise Application
$Scopes = "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"

$ExportPath = "C:\IntuneSettings"

Connect-MgGraph -Tenant $TenantID -AppId $AppID -Scopes $Scopes

####################################################

    Function Export-JSONData(){
    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>
    
    param (
        $JSON,
        $ExportPath
     )
    
        try {  
            if($JSON -eq "" -or $JSON -eq $null){
                write-host "No JSON specified, please specify valid JSON..." -f Red

            } elseif(!$ExportPath) {    
                write-host "No export path parameter set, please provide a path to export the file" -f Red    
            } elseif(!(Test-Path $ExportPath)) {
                write-host "$ExportPath doesn't exist, can't export JSON Data" -f Red
            } else {
                $JSON1 = ConvertTo-Json $JSON -Depth 10    
                $JSON_Convert = $JSON1 | ConvertFrom-Json    
                $displayName = $JSON_Convert.displayName
        
                # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
                $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"
        
                    # Added milliseconds to date format due to duplicate policy name
                    $FileName_JSON = "$DisplayName" + "_" + $(get-date -f dd-MM-yyyy-H-mm-ss.fff) + ".json"    
                    write-host "Export Path:" "$ExportPath"    
                    $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
                    write-host "JSON created in $ExportPath\$FileName_JSON..." -f cyan                
            }    
        }
    
        catch {    
            $_.Exception    
        }    
    }
    
####################################################
    
    Function Get-DeviceConfigurationPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
        try {    
            if($Name){    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=displayName eq '$name'"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value   
            } else {
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value    
            }    
        }
    
        catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
    }

####################################################
    Function Get-GroupPolicyConfigurations(){
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
        
        [cmdletbinding()]
        
        $graphApiVersion = "Beta"
        $DCP_resource = "deviceManagement/groupPolicyConfigurations"
        
        try
        {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
        }
        
        catch
        {
            
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
            
        }
        
    }
    
####################################################
    Function Get-GroupPolicyConfigurationsDefinitionValues(){
        
        <#
        .SYNOPSIS
        This function is used to get device configuration policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any device configuration policies
        .EXAMPLE
        Get-DeviceConfigurationPolicy
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Get-GroupPolicyConfigurations
        #>
        
        [cmdletbinding()]
        Param (
            
            [Parameter(Mandatory = $true)]
            [string]$GroupPolicyConfigurationID
            
        )
        
        $graphApiVersion = "Beta"
        #$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
        $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"
        
        
        try
        {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
        }
        
        catch
        {
            
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
            
        }
        
    }
    
####################################################
    Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues(){
        
        <#
        .SYNOPSIS
        This function is used to get device configuration policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any device configuration policies
        .EXAMPLE
        Get-DeviceConfigurationPolicy
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Get-GroupPolicyConfigurations
        #>
        
        [cmdletbinding()]
        Param (
            
            [Parameter(Mandatory = $true)]
            [string]$GroupPolicyConfigurationID,
            [string]$GroupPolicyConfigurationsDefinitionValueID
            
        )
        $graphApiVersion = "Beta"
        
        $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
        
        try
        {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
        }
        
        catch
        {
            
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
            
        }
        
    }
    
####################################################
    Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition (){
       <#
        .SYNOPSIS
        This function is used to get device configuration policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any device configuration policies
        .EXAMPLE
        Get-DeviceConfigurationPolicy
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Get-GroupPolicyConfigurations
        #>
        
        [cmdletbinding()]
        Param (
            
            [Parameter(Mandatory = $true)]
            [string]$GroupPolicyConfigurationID,
            [Parameter(Mandatory = $true)]
            [string]$GroupPolicyConfigurationsDefinitionValueID
            
        )
        $graphApiVersion = "Beta"
        $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
        
        try
        {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            
            $responseBody = Invoke-MgGraphRequest -Uri $uri -Method Get		
            
        }
        
        catch
        {
            
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
            
        }
        $responseBody
    }
    
####################################################
    Function Get-GroupPolicyDefinitionsPresentations (){
       <#
        .SYNOPSIS
        This function is used to get device configuration policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any device configuration policies
        .EXAMPLE
        Get-DeviceConfigurationPolicy
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Get-GroupPolicyConfigurations
        #>
        
        [cmdletbinding()]
        Param (		
            
            [Parameter(Mandatory = $true)]
            [string]$groupPolicyDefinitionsID,
            [Parameter(Mandatory = $true)]
            [string]$GroupPolicyConfigurationsDefinitionValueID
            
        )
        $graphApiVersion = "Beta"
        $DCP_resource = "deviceManagement/groupPolicyConfigurations/$groupPolicyDefinitionsID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues?`$expand=presentation"
        try
        {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            
            (Invoke-MgGraphRequest -Uri $uri -Method Get).Value.presentation
            
            
        }
        
        catch
        {
            
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
            
        }
        
    }
    
####################################################

    Function Get-SettingsCatalogPolicy(){

        <#
        .SYNOPSIS
        This function is used to get Settings Catalog policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any Settings Catalog policies
        .EXAMPLE
        Get-SettingsCatalogPolicy
        Returns any Settings Catalog policies configured in Intune
        Get-SettingsCatalogPolicy -Platform windows10
        Returns any Windows 10 Settings Catalog policies configured in Intune
        Get-SettingsCatalogPolicy -Platform macOS
        Returns any MacOS Settings Catalog policies configured in Intune
        .NOTES
        NAME: Get-SettingsCatalogPolicy
        #>
        
        [cmdletbinding()]
        
        param
        (
         [parameter(Mandatory=$false)]
         [ValidateSet("windows10","macOS")]
         [ValidateNotNullOrEmpty()]
         [string]$Platform
        )
        
        $graphApiVersion = "beta"
        
            if($Platform){        
                $Resource = "deviceManagement/configurationPolicies?`$filter=platforms has '$Platform' and technologies has 'mdm'"
            } else {
                $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"
            }
        
            try {
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        
            }
        
            catch {
        
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        
            }
        
    }
        
####################################################
        
    Function Get-SettingsCatalogPolicySettings(){
    
    <#
    .SYNOPSIS
    This function is used to get Settings Catalog policy Settings from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Settings Catalog policy Settings
    .EXAMPLE
    Get-SettingsCatalogPolicySettings -policyid policyid
    Returns any Settings Catalog policy Settings configured in Intune
    .NOTES
    NAME: Get-SettingsCatalogPolicySettings
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $policyid
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/configurationPolicies('$policyid')/settings?`$expand=settingDefinitions"
    
        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $Response = (Invoke-MgGraphRequest -Uri $uri -Method Get)
            $AllResponses = $Response.value     
            $ResponseNextLink = $Response."@odata.nextLink"
            while ($ResponseNextLink -ne $null){
                $Response = (Invoke-MgGraphRequest -Uri $uri -Method Get)
                $ResponseNextLink = $Response."@odata.nextLink"
                $AllResponses += $Response.value
            }
            return $AllResponses
        }
    
        catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
    }
   
####################################################

    Function Get-EndpointSecurityTemplate(){

    <#
    .SYNOPSIS
    This function is used to get all Endpoint Security templates using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all Endpoint Security templates
    .EXAMPLE
    Get-EndpointSecurityTemplate 
    Gets all Endpoint Security Templates in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityTemplate
    #>
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"
    
        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
        }
        
        catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
    }
    
####################################################
    
    Function Get-EndpointSecurityPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get all Endpoint Security policies using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all Endpoint Security templates
    .EXAMPLE
    Get-EndpointSecurityPolicy
    Gets all Endpoint Security Policies in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityPolicy
    #>    
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/intents"
    
        try {    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value    
        }
        
        catch {    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }    
    }
    
####################################################
    
    Function Get-EndpointSecurityTemplateCategory(){
    
    <#
    .SYNOPSIS
    This function is used to get all Endpoint Security categories from a specific template using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all template categories
    .EXAMPLE
    Get-EndpointSecurityTemplateCategory -TemplateId $templateId
    Gets an Endpoint Security Categories from a specific template in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityTemplateCategory
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $TemplateId
    )
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/templates/$TemplateId/categories"
    
        try {    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value    
        }
        
        catch {    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }  
    }
    
####################################################
    
    Function Get-EndpointSecurityCategorySetting(){
    
    <#
    .SYNOPSIS
    This function is used to get an Endpoint Security category setting from a specific policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a policy category setting
    .EXAMPLE
    Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
    Gets an Endpoint Security Categories from a specific template in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityCategory
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PolicyId,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $categoryId
    )
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/intents/$policyId/categories/$categoryId/settings?`$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value"
    
        try {    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
        }
        
        catch {    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break    
        }    
    }
    
####################################################

#region Output verification
    Function Verify-OutputPath(){
        If ($null -eq $ExportPath){
            $ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"
        }

        # If the directory path doesn't exist prompt user to create the directory
        $ExportPath = $ExportPath.replace('"','')

        if(!(Test-Path "$ExportPath")){
            Write-Host
            Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
            $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){
                new-item -ItemType Directory -Path "$ExportPath" | Out-Null
            Write-Host
            } else {
                Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
                Write-Host
                break
            }
        }
    }

#endregion

#region Export Functions

    Function Export-DeviceConfigurationPolicy(){
        $DCPs = Get-DeviceConfigurationPolicy | Where-Object { ($_.'@odata.type' -ne "#microsoft.graph.iosUpdateConfiguration") -and ($_.'@odata.type' -ne "#microsoft.graph.windowsUpdateForBusinessConfiguration") }
        foreach($DCP in $DCPs){
            write-host "Device Configuration Policy:"$DCP.displayName -f Yellow
            Export-JSONData -JSON $DCP -ExportPath "$ExportPath"
            Write-Host
        }
    }

    Function Export-GroupPolicy(){
        $DCPs = Get-GroupPolicyConfigurations

        foreach ($DCP in $DCPs){
            $FolderName = $($DCP.displayName) -replace '\[|\]|\<|\>|:|"|/|\\|\||\?|\*', "_"
            New-Item "$ExportPath\$($FolderName)" -ItemType Directory -Force
            
            $GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $DCP.id
            foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues)
            {
                $GroupPolicyConfigurationsDefinitionValue
                $DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                $DefinitionValuedefinitionID = $DefinitionValuedefinition.id
                $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinition.displayName
                $GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                $DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                $OutDef = New-Object -TypeName PSCustomObject
                $OutDef | Add-Member -MemberType NoteProperty -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')"
                $OutDef | Add-Member -MemberType NoteProperty -Name "enabled" -value $($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().tolower())
                if ($DefinitionValuePresentationValues) {
                    $i = 0
                    $PresValues = @()
                    foreach ($Pres in $DefinitionValuePresentationValues) {
                        $P = $pres | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                        $GPDPID = $groupPolicyDefinitionsPresentations[$i].id
                        $P | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')/presentations('$GPDPID')"
                        $PresValues += $P
                        $i++
                    }
                    $OutDef | Add-Member -MemberType NoteProperty -Name "presentationValues" -Value $PresValues
                }
                $FileName = (Join-Path $DefinitionValuedefinition.categoryPath $($definitionValuedefinitionDisplayName)) -replace '\[|\]|\<|\>|:|"|/|\\|\||\?|\*', "_"
                $OutDefjson = ($OutDef | ConvertTo-Json -Depth 10).replace("\u0027","'")
                $OutDefjson | Out-File -FilePath "$ExportPath\$($folderName)\$fileName.json" -Encoding ascii
            }
        }   
    }

    Function Export-SettingsCatalog(){
        $Policies = Get-SettingsCatalogPolicy

        if($Policies){

            foreach($policy in $Policies){

                Write-Host $policy.name -ForegroundColor Yellow

                $AllSettingsInstances = @()

                $policyid = $policy.id
                $Policy_Technologies = $policy.technologies
                $Policy_Platforms = $Policy.platforms
                $Policy_Name = $Policy.name
                $Policy_Description = $policy.description
                $PolicyBody = New-Object -TypeName PSObject

                Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'name' -Value "$Policy_Name"
                Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'description' -Value "$Policy_Description"
                Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'platforms' -Value "$Policy_Platforms"
                Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'technologies' -Value "$Policy_Technologies"

                # Checking if policy has a templateId associated
                if($policy.templateReference.templateId){

                    Write-Host "Found template reference" -f Cyan
                    $templateId = $policy.templateReference.templateId
                    $PolicyTemplateReference = New-Object -TypeName PSObject
                    Add-Member -InputObject $PolicyTemplateReference -MemberType 'NoteProperty' -Name 'templateId' -Value $templateId
                    Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'templateReference' -Value $PolicyTemplateReference
                }

                $SettingInstances = Get-SettingsCatalogPolicySettings -policyid $policyid
                $Instances = $SettingInstances.settingInstance
                foreach($object in $Instances){
                    $Instance = New-Object -TypeName PSObject
                    Add-Member -InputObject $Instance -MemberType 'NoteProperty' -Name 'settingInstance' -Value $object
                    $AllSettingsInstances += $Instance
                }

                Add-Member -InputObject $PolicyBody -MemberType 'NoteProperty' -Name 'settings' -Value @($AllSettingsInstances)
                Export-JSONData -JSON $PolicyBody -ExportPath "$ExportPath"
                Write-Host
            }
        } else {
            Write-Host "No Settings Catalog policies found..." -ForegroundColor Red
            Write-Host
        }
    }

    Function Export-EndpointSecurityConfigurations(){

        # Get all Endpoint Security Templates
        $Templates = Get-EndpointSecurityTemplate

        # Get all Endpoint Security Policies configured
        $ESPolicies = Get-EndpointSecurityPolicy | Sort-Object displayName

        # Looping through all policies configured
        foreach($policy in $ESPolicies){

            Write-Host "Endpoint Security Policy:"$policy.displayName -ForegroundColor Yellow
            $PolicyName = $policy.displayName
            $PolicyDescription = $policy.description
            $policyId = $policy.id
            $TemplateId = $policy.templateId
            $roleScopeTagIds = $policy.roleScopeTagIds

            $ES_Template = $Templates | ?  { $_.id -eq $policy.templateId }

            $TemplateDisplayName = $ES_Template.displayName
            $TemplateId = $ES_Template.id
            $versionInfo = $ES_Template.versionInfo

            if($TemplateDisplayName -eq "Endpoint detection and response"){
                Write-Host "Export of 'Endpoint detection and response' policy not included in sample script..." -ForegroundColor Magenta
                Write-Host
            } else {

                # Creating object for JSON output
                $JSON = New-Object -TypeName PSObject

                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'displayName' -Value "$PolicyName"
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'description' -Value "$PolicyDescription"
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'roleScopeTagIds' -Value $roleScopeTagIds
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateDisplayName' -Value "$TemplateDisplayName"
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateId' -Value "$TemplateId"
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'versionInfo' -Value "$versionInfo"

                # Getting all categories in specified Endpoint Security Template
                $Categories = Get-EndpointSecurityTemplateCategory -TemplateId $TemplateId

                # Looping through all categories within the Template
                foreach($category in $Categories){
                    $categoryId = $category.id
                    $Settings += Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId           
                }

                # Adding All settings to settingsDelta ready for JSON export
                Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'settingsDelta' -Value @($Settings)

                Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
                Write-Host

                # Clearing up variables so previous data isn't exported in each policy
                Clear-Variable JSON
                Clear-Variable Settings

            }

        }
    }

#endregion

Verify-OutputPath
Export-DeviceConfigurationPolicy
Export-GroupPolicy
Export-SettingsCatalog
Export-EndpointSecurityConfigurations