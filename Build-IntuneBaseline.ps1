<##################################################################################################
#
.SYNOPSIS
This script creates a foundational configuration of Intune in accordance with CIS v8 benchmarks
for Windows devices in Intune, specifically L1, IG1.
    - Device Configuration Profiles
    - Settings Catalog
    - Administrative Templates
    - Endpoint Security profiles (BitLocker and Windows Firewall)

Additional settings are included for configuration of OneDrive KFM, AutoPilot deployment profiles,
Device Compliance policy, and creating a basic list of security groups.

Some functions in this script are adapted from Microsoft's published Intune samples on GitHub. The
adaptations are primarily to use cmdlets native to Microsoft.Graph SDK. The samples can be found at:
https://github.com/microsoftgraph/powershell-intune-samples

.NOTES
    FileName:               Build-IntuneBaseline.ps1
    Author:                 Jesse Russell
    Created:                2023.10.12
	Revised:                
    Version:                1.0
    PS Modules required:    Microsoft.Graph SDK
    
    NOTE:                   

    Limitations:            No configuration for non-Windows devices at this time
                            Windows Update Rings configuration not included at this time
                            Windows Information Protection policies will be added
#>

###################################################################################################

$TenantID = "" 
$AppID = "14d82eec-204b-4c2f-b7e8-296a70dab67e" # Default Microsoft Graph PowerShell Enterprise Application
$Scopes = "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"

$ImportBasePath = ".\JSON"

# $psMajorVersion = 
Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0.0
Import-Module Microsoft.Graph.Groups -MinimumVersion 2.0.0.0

####################################################
function Catch-Error {
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

Function Test-JSON() {
		
	<#
	.SYNOPSIS
	This function is used to test if the JSON passed to a REST Post request is valid
	.DESCRIPTION
	The function tests if the JSON passed to the REST Post is valid
	.EXAMPLE
	Test-JSON -JSON $JSON
	Test if the JSON is valid before calling the Graph REST interface
	.NOTES
	NAME: Test-AuthHeader
	#>
		
		param (			
			$JSON			
		)
		
		try	{			
			$TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
			$validJson = $true			
		}
		
		catch {			
			$validJson = $false
			$_.Exception			
		}
		
		if (!$validJson){			
			Write-Host "Provided JSON isn't in valid JSON format" -f Red
			break			
		}		
}

Function New-IntuneDefaultGroups {

    <#
    .SYNOPSIS
    This function is used to add Intune - All Devices, Intune - All Users, and Intune - Autopilot Exempt per current Resultant standards
    .DESCRIPTION
    The function connects to Azure AD to create a standard group set
    .EXAMPLE
    New-IntuneDefaultGroups
    Adds Resultant standard default group structure
    .NOTES
    NAME:New-IntuneDefaultGroups
    #>
    
    # Update with any specific membership rules for the Intune - All Devices group
    $membership = '(device.deviceOwnership -contains "Company") and (device.deviceOSType -contains "Windows")'

    # Create default group set
    New-MgGroup -DisplayName "Intune - All Users" -MailEnabled:$false -MailNickName "IntuneAllUsers" -SecurityEnabled
    New-MgGroup -DisplayName "Intune - Autopilot Exempt" -MailEnabled:$false -MailNickName "IntuneAPExempt" -SecurityEnabled
    New-MgGroup -DisplayName "Intune - Windows Devices" `
        -MailEnabled:$false `
        -MailNickname "IntuneAllDevices" `
        -SecurityEnabled `
        -GroupTypes "DynamicMembership" `
        -MembershipRule $membership `
        -MembershipRuleProcessingState "On" `
        -IsAssignableToRole:$false
}

####################################################

Function Add-DeviceCompliancePolicyBaseline(){
    
    <#
    .SYNOPSIS
    This function is used to add a device compliance policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy
    .EXAMPLE
    Add-DeviceCompliancePolicy -Source "<filename>.JSON"
    Adds a device compliance policy in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicy
    #>
        
    [cmdletbinding()]
        
    param
    (
        $Source
    )
    
    $JSON = Get-Content -Raw "$ImportBasePath\DeviceCompliance\$source"
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
    try {        
        if($JSON -eq "" -or $null -eq $JSON){        
            write-host "No Device Compliance Policy specified, please specify valid JSON" -f Red        
        } else {        
            #Test-JSON -JSON $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" 
        }
    }
    
    catch {
        Catch-Error
    }        
}

####################################################

Function Add-DeviceConfigurationProfile(){

    <#
    .SYNOPSIS
    This function is used to add a device configuration policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy
    .EXAMPLE
    Add-DeviceConfigurationPolicy -Source $folderpath\<example>.json
    .NOTES
    NAME: Add-DeviceConfigurationPolicy
    #>

    [cmdletbinding()]
    param
    (
        $Source
    )

    $JSON = Get-Content -Raw "$ImportBasePath\DeviceConfigs\$Source" 
    Write-Host $source
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    Write-Verbose "Resource: $DCP_resource"

    try {    
        if($JSON -eq "" -or $null -eq $JSON){
            write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red
        } else {
            $JSON_Convert = $JSON | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
		    $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 10
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON_Output -ContentType "application/json"
        }    
    } catch {
        Catch-Error  
    }    
}

####################################################

Function Add-EndpointSecurity(){

    <#
        Get endpoint templates
        Initialize JSON
        Evaluate source against security baseline or deprecated template
        Add security settings
    #>

    param (
        $source
    )

    function Initialize-JSON {
        # $folderpath = "$ImportBasePath\Security"
        $JSON = Get-Content -Raw "$ImportBasePath\Security\$source"
        
        # Converting input to JSON format
        $JSON_Convert = $JSON | ConvertFrom-Json

        # Pulling out variables to use in the import
        $JSON_Name = $JSON_Convert.displayName
        $JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
        $JSON_TemplateId = $JSON_Convert.templateId

        Write-Host
        Write-Host "Endpoint Security Policy '$JSON_Name' found..." -ForegroundColor Cyan
        Write-Host "Template Display Name: $JSON_TemplateDisplayName"
        Write-Host "Template ID: $JSON_TemplateId"

        # Excluding certain properties from JSON that aren't required for import
        $JSON_Select = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName,TemplateId,versionInfo
        $DisplayName = $JSON_Select.displayName
        $JSON_Output = $JSON_Select | ConvertTo-Json -Depth 10
        write-host
        $JSON_Output
        write-host
        Write-Host "Adding Endpoint Security Policy '$DisplayName'" -ForegroundColor Yellow
    }

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
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value 
        }    
        catch {
            Catch-Error
        }
    }

    Function Compare-JSONSource(){
        
        # Get all Endpoint Security Templates
        $Templates = Get-EndpointSecurityTemplate

        # Checking if templateId from JSON is a valid templateId
        $ES_Template = $Templates | Where-Object  { $_.id -eq $JSON_TemplateId }

        # If template is a baseline Edge, MDATP or Windows, use templateId specified
        if(($ES_Template.templateType -eq "microsoftEdgeSecurityBaseline") -or ($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){
            $TemplateId = $JSON_Convert.templateId

        # Else If not a baseline, check if template is deprecated   
        } elseif($ES_Template){ 

            # if template isn't deprecated use templateId
            if($ES_Template.isDeprecated -eq $false){
                $TemplateId = $JSON_Convert.templateId
            
            # If template deprecated, look for lastest version
            } elseif($ES_Template.isDeprecated -eq $true) { 
                $Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }
                $Template = $Template | Where-Object { $_.isDeprecated -eq $false }
                $TemplateId = $Template.id
            }
        }

        # Else If Imported JSON template ID can't be found check if Template Display Name can be used
        elseif($null -eq $ES_Template){

            Write-Host "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used..." -ForegroundColor Red
            $ES_Template = $Templates | Where-Object  { $_.displayName -eq "$JSON_TemplateDisplayName" }

            If($ES_Template){
                if(($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){
                    Write-Host
                    Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
                    Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
                    Write-Host
                    break
                } else {
                    Write-Host "Template with displayName '$JSON_TemplateDisplayName' found..." -ForegroundColor Green
                    $Template = $ES_Template | Where-Object { $_.isDeprecated -eq $false }
                    $TemplateId = $Template.id
                }
            } else {
                Write-Host
                Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
                Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
                Write-Host
                break
            }
        }
    } 

    Function Add-EndpointSecurityPolicy(){

        <#
        .SYNOPSIS
        This function is used to add an Endpoint Security policy using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds an Endpoint Security  policy
        .EXAMPLE
        Add-EndpointSecurityDiskEncryptionPolicy -JSON $JSON -TemplateId $templateId
        Adds an Endpoint Security Policy in Endpoint Manager
        .NOTES
        NAME: Add-EndpointSecurityPolicy
        #>

        [cmdletbinding()]

        param
        (
            $TemplateId,
            $JSON
        )

        $graphApiVersion = "Beta"
        $ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
        Write-Verbose "Resource: $ESP_resource"

        try {
            if($JSON -eq "" -or $null -eq $JSON){
                write-host "No JSON specified, please specify valid JSON for the Endpoint Security Policy..." -f 
            } else {
                Test-JSON -JSON $JSON
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
                Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" 
            }
        }     
        catch {
            Catch-Error
        }
    }

    ####################################################
    Initialize-JSON
    Compare-JSONSource
    Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON_Output
   
}

####################################################

Function Add-GroupPolicy(){

}

####################################################
###                 Let 'er rip                  ###
####################################################

Connect-MgGraph -Tenant $TenantID -AppId $AppID -Scopes $Scopes -NoWelcome

# Create standard default groups
New-IntuneDefaultGroups

# Create default AutoPilot profile
Add-DefaultAutoPilotProfile -Source "Default AutoPilot Deployment.json"

# Create default Device Compliance Policy
Add-DeviceCompliancePolicyBaseline -Source "BaselineWin10.json"

# Create device configuration profiles
Add-DeviceConfigurationProfile -Source "Windows - CIS Benchmark 1 - Account Policies_13-10-2023-16-34-44.400.json"

# Create ADMX/Group Policy settings

# Create Settings Catalog profiles

# Create Endpoint Security profiles
Add-EndpointSecurity -source "BitLocker Baseline Policy_13-10-2023-16-34-54.734.json"

####################################################
###                Future State                  ###
####################################################

### Need to break Initialize-JSON out into a separate function from the Add-EndpointSecurity function
### Appears to be required for device compliance profile to work correctly, probably needed for others

####################################################