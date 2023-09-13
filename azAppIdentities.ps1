# Report on application identities being used to authenticate against Azure AD (Entra ID).
# These are usually used to automate tasks. For each application with app credentials, returns associated scopes, roles and azure resources access
# requires module Az:
# Install-Module Az

Connect-AzAccount
$today = Get-Date

# Get all app registrations having key or password credentials. These are created to run automated tasks as apps and 
$Apps = Get-AzADApplication | Where-Object -FilterScript {($_.KeyCredentials.Count -GT 0) -or ($_.PasswordCredentials.Count -GT 0)}

# Retrieve all service principals in Azure AD
$allSPs = Get-AzADServicePrincipal
# Retrieve all RBAC role assignments in Azure AD
$allRoleAssignments = Get-AzRoleAssignment

$appIdentities=@()
$Apps | ForEach-Object {
    $App = $_
    # Only consider if the key or password credentials are still valid. Otherwise we'll skip the app
    if( ($App.PasswordCredentials | Where-Object -FilterScript {[DateTime]$_.EndDateTime -ge $today}).Count -or
      ($App.KeyCredentials | Where-Object -FilterScript {[DateTime]$_.EndDateTime -ge $today}).Count) {
        # Get Key and Password Credentials for app
        $appCredentials=""
        $App.KeyCredentials | ForEach-Object {
            if([DateTime]$_.EndDateTime -ge $today) {
                $appCredentials += $_.DisplayName + " (exp. " + $_.EndDateTime.ToString("yyyy-MM-dd") + ", Key Credential)" + "`n"
            }
        }
        $App.PasswordCredentials | ForEach-Object {
            if([DateTime]$_.EndDateTime -ge $today) {
                $appCredentials += $_.DisplayName + " (exp. " + $_.EndDateTime.ToString("yyyy-MM-dd") + ", Password Credential)" + "`n"
            }
        }

        # List API permissions (scopes and roles) for app, then resolve each permission name within each scope/role
        $appPermissions=""
        #$App.RequiredResourceAccess | Format-List
        $App.RequiredResourceAccess | ForEach-Object{
            $requiredResource=$_.ResourceAppId
            $permissionsForResource=$_.ResourceAccess 
            $requiredSP=$allSPs | Where-Object -FilterScript {$_.AppId -EQ $requiredResource}
            $appPermissions += $requiredSP.DisplayName + ": "
            $permissionsForResource | ForEach-Object {
                $permission = $_.Id
                $scopeResolved=$requiredSP.Oauth2PermissionScope | Where-Object -FilterScript {$_.id -EQ $permission}
                if($scopeResolved) {$appPermissions += $scopeResolved.Value + " (" + $_.Type + "); "}
                $roleResolved=$requiredSP.AppRole | Where-Object -FilterScript {$_.id -EQ $permission}
                if($roleResolved) {$appPermissions += $roleResolved.Value + " (" + $_.Type + "); "}

            }
            $appPermissions += "`n"
            #$requiredSP
        }
        # Get the Service Principal (SP) for the application. Azure Roles are assigned to SP
        $AppSPid = ($allSPs | Where-Object -FilterScript {$_.AppId -EQ $App.AppId}).Id
        # Get all Azure built in roles where the app is assigned to
        $appRolesAssigned=""
        $appRoles = $allRoleAssignments | Where-Object -FilterScript {$_.ObjectId -EQ $AppSPid}
        $appRoles | ForEach-Object {
            $appRolesAssigned += $_.RoleDefinitionName + ": " + $_.Scope + "`n"
        }

        # Add each entry as custom object with properties
        $appIdentities += [PSCustomObject] @{            
            AppDisplayName = $App.DisplayName;
            AppId = $app.AppId;
            AppCredentials = $appCredentials;
            APIPermissions = $appPermissions;
            AzureRolesWithResources = $appRolesAssigned;
            }
    }
}

$appIdentities | Format-List
