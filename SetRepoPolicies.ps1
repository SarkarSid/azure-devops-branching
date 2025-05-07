param (
    [Parameter(Mandatory=$true)][string]$RepositoryName,
    [Parameter(Mandatory=$true)][string]$OrganizationUrl,
    [Parameter(Mandatory=$true)][string]$ProjectName,
    [Parameter(Mandatory=$true)][string]$PersonalAccessToken
)

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

function Invoke-AzureDevOpsApi {
    param (
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$false)][string]$Method = "Get",
        [Parameter(Mandatory=$true)][string]$PersonalAccessToken,
        [Parameter(Mandatory=$false)][object]$Body = $null,
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3
    )
    
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PersonalAccessToken"))
    $headers = @{
        Authorization = "Basic $base64AuthInfo"
        Accept = "application/json"
    }
    
    $params = @{
        Uri = $Url
        Headers = $headers
        Method = $Method
        UseBasicParsing = $true
    }
    
    if ($Method -in "Post","Put" -and $Body) {
        $jsonBody = $Body | ConvertTo-Json -Depth 10
        $params.Add("Body", $jsonBody)
        $params.Add("ContentType", "application/json")
    }
    
    $retryCount = 0
    $waitTime = 2
    
    do {
        try {
            Write-Verbose "Calling Azure DevOps API: $Url"
            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $errorMessage = $_.ErrorDetails.Message
            
            if ($statusCode -eq 429 -or $statusCode -ge 500) {
                $waitTime = [math]::Min(30, $waitTime * 2)
                Write-Warning "API error ($statusCode). Retrying in $waitTime seconds..."
            }
            elseif ($errorMessage -match "TF402457") {
                Write-Error "Policy settings format error: $errorMessage"
                throw
            }
            else {
                Write-Warning "API call failed: $statusCode - $errorMessage"
            }
            
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Write-Error "API call failed after $MaxRetries attempts."
                throw
            }
            
            Start-Sleep -Seconds $waitTime
        }
    } while ($retryCount -lt $MaxRetries)
}

if (-not [System.Uri]::IsWellFormedUriString($OrganizationUrl, [System.UriKind]::Absolute)) {
    Write-Error "The provided OrganizationUrl is invalid: $OrganizationUrl"
    exit 1
}

$repoUrl = "$OrganizationUrl/$ProjectName/_apis/git/repositories?api-version=7.1"
$repos = Invoke-AzureDevOpsApi -Url $repoUrl -PersonalAccessToken $PersonalAccessToken
$repository = $repos.value | Where-Object { $_.name -eq $RepositoryName }

if (-not $repository) {
    Write-Error "Repository '$RepositoryName' not found in project '$ProjectName'"
    exit 1
}

$RepositoryId = $repository.id
Write-Host "Found repository ID: $RepositoryId"

function Test-RepositoryPermissions {
    param (
        [string]$RepositoryId,
        [string]$OrganizationUrl,
        [string]$ProjectName,
        [string]$PersonalAccessToken
    )

    $permissionsToCheck = @(
        @{ name = 'Force Push'; bit = 4 },
        @{ name = 'Edit Policies'; bit = 2 },
        @{ name = 'Bypass policies when completing pull requests'; bit = 16384 },
        @{ name = 'Bypass policies when pushing'; bit = 8192 }
    )
    
    $securityNamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
    $projectsUrl = "$OrganizationUrl/_apis/projects/$ProjectName`?api-version=7.1"
    $projectInfo = Invoke-AzureDevOpsApi -Url $projectsUrl -PersonalAccessToken $PersonalAccessToken
    
    if (-not $projectInfo -or -not $projectInfo.id) {
        Write-Error "Could not retrieve project information for $ProjectName"
        return $false
    }
    
    $projectId = $projectInfo.id
    $token = "repoV2/$RepositoryId"
    
    $securityGroups = @(
        @{displayName = "Project Administrators"; descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-3-0-0-0-1"},
        @{displayName = "Contributors"; descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-2-0-0-0-1"},
        @{displayName = "Readers"; descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-1-0-0-0-1"},
        @{displayName = "Project Valid Users"; descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-0-0-0-0-0"},
        @{displayName = "Everyone"; descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1204400969-2402986413-2179408616-0-0-0-0-1"}
    )

    foreach ($group in $securityGroups) {
        Write-Host "Checking '$($group.displayName)' permissions..."
        
        foreach ($permission in $permissionsToCheck) {
            $url = "$OrganizationUrl/_apis/accesscontrolentries/$securityNamespaceId/?api-version=7.1"
            $body = @{
                token = $token
                descriptors = @($group.descriptor)
                includeExtendedInfo = $true
            }
            try {
                $response = Invoke-AzureDevOpsApi -Url $url -Method Post -Body $body -PersonalAccessToken $PersonalAccessToken
                
                # Check if this group has ACLs for this token
                $acl = $responseac.value | Where-Object { $_.descriptor -eq $group.descriptor }
                
                if ($acl) {
                    # Check the effective permissions
                    $isDenied = ($acl.extendedInfo.effectiveAllow -band $permission.bit) -eq 0 -and 
                               ($acl.extendedInfo.effectiveDeny -band $permission.bit) -ne 0
                    
                    $status = if ($isDenied) { "DENIED" } else { "NOT DENIED" }
                    Write-Host "  $($permission.name): $status"
                }
                else {
                    Write-Host "  $($permission.name): No specific ACL found"
                }
            }
            catch {
                Write-Warning "Failed to check $($permission.name): $_"
            }
        }
    }
    
    return $true
}

function Get-DefaultBranch {
    param (
        [string]$RepositoryId,
        [string]$OrganizationUrl,
        [string]$ProjectName,
        [string]$PersonalAccessToken
    )
    
    $repoUrl = "$OrganizationUrl/$ProjectName/_apis/git/repositories/$RepositoryId`?api-version=7.1"
    $response = Invoke-AzureDevOpsApi -Url $repoUrl -PersonalAccessToken $PersonalAccessToken
    
    if ($response -and $response.defaultBranch) {
        return $response.defaultBranch
    }
    
    return "refs/heads/main"
}

function Set-RepositoryPermissions {
    param (
        [string]$RepositoryId,
        [string]$DefaultBranch,
        [string]$OrganizationUrl,
        [string]$ProjectName,
        [string]$PersonalAccessToken
    )
    
    $projectsUrl = "$OrganizationUrl/_apis/projects/$ProjectName`?api-version=7.1"
    $projectInfo = Invoke-AzureDevOpsApi -Url $projectsUrl -PersonalAccessToken $PersonalAccessToken
    $projectId = $projectInfo.id
    
    $namespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
    $token = "repoV2/$RepositoryId/$DefaultBranch"
    
    $securityGroups = @(
        @{
            displayName = "Contributors"
            descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-2-0-0-0-1"
            allow = 1
            deny = 24582
        },
        @{
            displayName = "Readers"
            descriptor = "Microsoft.TeamFoundation.Identity;S-1-9-1551374245-$projectId-1-0-0-0-1"
            allow = 0
            deny = 24582
        }
    )
    
    foreach ($group in $securityGroups) {
        Write-Host "Setting permissions for $($group.displayName)..."
        
        $aclUrl = "$OrganizationUrl/_apis/AccessControlEntries/$namespaceId`?api-version=7.1-preview.1"
        $body = @{
            token = $token
            merge = $true
            accessControlEntries = @(
                @{
                    descriptor = $group.descriptor
                    allow = $group.allow
                    deny = $group.deny
                }
            )
        }
        
        Invoke-AzureDevOpsApi -Url $aclUrl -Method Post -Body $body -PersonalAccessToken $PersonalAccessToken
    }
    
    return $true
}

function Set-RepositoryPolicies {
    param (
        [string]$RepositoryId,
        [string]$DefaultBranch,
        [string]$OrganizationUrl,
        [string]$ProjectName,
        [string]$PersonalAccessToken
    )
    
    $commonScope = @(@{
        repositoryId = $RepositoryId
        refName = $DefaultBranch
        matchKind = "Exact"
    })
    
    $policies = @(
        @{
            name = 'Minimum number of reviewers'
            typeId = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd'
            settings = @{
                minimumApproverCount = 2
                creatorVoteCounts = $false
                allowDownvotes = $false
                resetOnSourcePush = $true
                requireVoteOnLastIteration = $false
                resetRejectionsOnSourcePush = $false
                blockLastPusherVote = $false
                scope = $commonScope
            }
        },
        @{
            name = 'Comment requirements'
            typeId = 'c6a1889d-b943-4856-b76f-9e46bb6b0df2'
            settings = @{
                blockCommentsDuringPullRequestCompletion = $true
                scope = $commonScope
            }
        },
        @{
            name = 'Work item linking'
            typeId = '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e'
            settings = @{
                scope = $commonScope
            }
        }
    )

    foreach ($policy in $policies) {
        Write-Host "Setting policy: $($policy.name)"
        $url = "$OrganizationUrl/$ProjectName/_apis/policy/configurations?api-version=7.1-preview.1"

        $body = @{
            isEnabled = $true
            isBlocking = $true
            type = @{
                id = $policy.typeId
            }
            settings = $policy.settings
        }
        
        try {
            Invoke-AzureDevOpsApi -Url $url -Method Post -Body $body -PersonalAccessToken $PersonalAccessToken
        }
        catch {
            Write-Warning "Failed to set policy $($policy.name): $_"
        }
    }
}

# Main script execution
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Starting repository configuration for $RepositoryName in $ProjectName"

# Validate permissions
Test-RepositoryPermissions -RepositoryId $RepositoryId -OrganizationUrl $OrganizationUrl -ProjectName $ProjectName -PersonalAccessToken $PersonalAccessToken

# Get default branch
$defaultBranch = Get-DefaultBranch -RepositoryId $RepositoryId -OrganizationUrl $OrganizationUrl -ProjectName $ProjectName -PersonalAccessToken $PersonalAccessToken
Write-Host "Using branch: $defaultBranch"

# Track operations
$operationsCompleted = @()
$operationsFailed = @()

# Set permissions
try {
    Set-RepositoryPermissions -RepositoryId $RepositoryId -DefaultBranch $defaultBranch -OrganizationUrl $OrganizationUrl -ProjectName $ProjectName -PersonalAccessToken $PersonalAccessToken
    $operationsCompleted += "PermissionConfiguration"
} catch {
    $operationsFailed += "PermissionConfiguration"
}

# Set policies
try {
    Set-RepositoryPolicies -RepositoryId $RepositoryId -DefaultBranch $defaultBranch -OrganizationUrl $OrganizationUrl -ProjectName $ProjectName -PersonalAccessToken $PersonalAccessToken
    $operationsCompleted += "PolicyConfiguration"
} catch {
    $operationsFailed += "PolicyConfiguration"
}

# Summary
Write-Host "=== Configuration Summary ==="
Write-Host "Repository: $RepositoryName"
Write-Host "Project: $ProjectName"
Write-Host "Default Branch: $defaultBranch"

if ($operationsCompleted.Count -gt 0) {
    Write-Host "Successful operations: $($operationsCompleted -join ', ')"
}

if ($operationsFailed.Count -gt 0) {
    Write-Host "Failed operations: $($operationsFailed -join ', ')"
    if ($operationsCompleted.Count -eq 0) {
        exit 1
    }
}