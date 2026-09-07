#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[^/]+/[^/]+$')]
    [string] $Repository = $env:GITHUB_REPOSITORY,

    [Parameter()]
    [string] $Name = 'main-protection',

    [Parameter()]
    [string] $Replace,

    [Parameter()]
    [string] $Branch,

    [Parameter()]
    [ValidateSet('active', 'disabled')]
    [string] $Enforcement = 'active',

    [Parameter()]
    [ValidateRange(0, 6)]
    [int] $Approvals = 1,

    [Parameter()]
    [string[]] $BypassUser = @(),

    [Parameter()]
    [string[]] $Check = @(),

    [Parameter()]
    [string[]] $Environment = @('dev', 'stg', 'pro'),

    [Parameter()]
    [string[]] $ApprovalEnvironment = @('stg', 'pro'),

    [Parameter()]
    [string[]] $EnvironmentReviewerUser = @('oriolcanades'),

    [Parameter()]
    [string[]] $EnvironmentReviewerTeam = @('in2workspace/kizunaops'),

    [Parameter()]
    [string[]] $RequiredSecret = @(
        'AWS_ACCESS_KEY_ID_DEV',
        'AWS_ACCESS_KEY_ID_PRO',
        'AWS_ACCESS_KEY_ID_STG',
        'AWS_ECR_REPOSITORY',
        'AWS_REGION',
        'AWS_SECRET_ACCESS_KEY_DEV',
        'AWS_SECRET_ACCESS_KEY_PRO',
        'AWS_SECRET_ACCESS_KEY_STG',
        'SONAR_TOKEN'
    ),

    [Parameter()]
    [switch] $SkipSecretCheck,

    [Parameter()]
    [switch] $SkipEnvironments,

    [Parameter()]
    [switch] $DeleteClassicProtection,

    [Parameter()]
    [switch] $NoCodeScanning,

    [Parameter()]
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

$DefaultChecks = @(
    'application-ci / Build & Test'
    'application-ci / ZAP DAST Baseline'
    'license-compliance / License Compliance Check'
    'analyze / Analyze (java)'
)

if ([string]::IsNullOrWhiteSpace($Repository)) {
    throw 'Provide -Repository OWNER/REPO or set GITHUB_REPOSITORY.'
}

if ($DeleteClassicProtection -and $Enforcement -ne 'active') {
    throw 'Classic protection can only be deleted when the replacement ruleset is active.'
}

$unknownApprovalEnvironments = @(
    $ApprovalEnvironment | Where-Object { $_ -notin $Environment }
)
if ($unknownApprovalEnvironments.Count -gt 0) {
    throw "Approval environments must also be listed in -Environment: $($unknownApprovalEnvironments -join ', ')."
}

if ($Check.Count -eq 0) {
    $Check = $DefaultChecks
}

$repositoryParts = $Repository.Split('/')
$owner = $repositoryParts[0]
$repo = $repositoryParts[1]
$apiBase = "https://api.github.com/repos/$owner/$repo"
$token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }

$headers = @{
    Accept                  = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2026-03-10'
    'User-Agent'            = 'eudistack-repository-settings'
}

if ($token) {
    $headers.Authorization = "Bearer $token"
}

function Invoke-GitHubApi {
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [Parameter()]
        [ValidateSet('Get', 'Post', 'Put', 'Delete')]
        [string] $Method = 'Get',

        [Parameter()]
        [object] $Body
    )

    $parameters = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 20
    }

    Invoke-RestMethod @parameters
}

if (-not $DryRun -and -not $token) {
    throw 'Set GH_TOKEN or GITHUB_TOKEN to a token with repository Administration read/write and Secrets read permission.'
}

$bypassActors = @()
$branchPattern = if ($Branch) { "refs/heads/$Branch" } else { '~DEFAULT_BRANCH' }
$rules = @(
    @{ type = 'deletion' }
    @{ type = 'non_fast_forward' }
    @{ type = 'required_linear_history' }
    @{
        type       = 'pull_request'
        parameters = @{
            allowed_merge_methods              = @('squash')
            dismiss_stale_reviews_on_push      = $true
            require_code_owner_review          = $true
            require_last_push_approval         = $true
            required_approving_review_count    = $Approvals
            required_review_thread_resolution  = $true
        }
    }
    @{
        type       = 'required_status_checks'
        parameters = @{
            do_not_enforce_on_create              = $false
            required_status_checks                = @(
                $Check | ForEach-Object { @{ context = $_ } }
            )
            strict_required_status_checks_policy = $true
        }
    }
)

if (-not $NoCodeScanning) {
    $rules += @{
        type       = 'code_scanning'
        parameters = @{
            code_scanning_tools = @(
                @{
                    tool                      = 'CodeQL'
                    security_alerts_threshold = 'high_or_higher'
                    alerts_threshold          = 'errors'
                }
            )
        }
    }
}

$payload = @{
    name          = $Name
    target        = 'branch'
    enforcement   = $Enforcement
    bypass_actors = $bypassActors
    conditions    = @{
        ref_name = @{
            include = @($branchPattern)
            exclude = @()
        }
    }
    rules         = $rules
}

if ($DryRun) {
    @{
        ruleset = $payload
        unresolved_bypass_users = $BypassUser
        environments = if ($SkipEnvironments) {
            @()
        }
        else {
            @(
                $Environment | ForEach-Object {
                    @{
                        name = $_
                        requires_approval = $_ -in $ApprovalEnvironment
                        reviewer_users = $EnvironmentReviewerUser
                        reviewer_teams = $EnvironmentReviewerTeam
                        prevent_self_review = $_ -in $ApprovalEnvironment
                    }
                }
            )
        }
        required_repository_secrets = if ($SkipSecretCheck) { @() } else { $RequiredSecret }
    } | ConvertTo-Json -Depth 20
    return
}

if (-not $SkipSecretCheck) {
    $repositorySecretNames = @()
    $page = 1

    do {
        $secretPage = Invoke-GitHubApi `
            -Uri "$apiBase/actions/secrets?per_page=100&page=$page"
        $repositorySecretNames += @($secretPage.secrets | ForEach-Object { $_.name })
        $page += 1
    }
    while ($repositorySecretNames.Count -lt $secretPage.total_count)

    $missingSecrets = @(
        $RequiredSecret | Where-Object { $_ -notin $repositorySecretNames }
    )
    if ($missingSecrets.Count -gt 0) {
        throw "Missing required repository secrets: $($missingSecrets -join ', ')."
    }

    Write-Host "Verified $($RequiredSecret.Count) required repository secrets."
}

$resolvedUsers = @{}
function Resolve-GitHubUser {
    param(
        [Parameter(Mandatory)]
        [string] $Login
    )

    if (-not $resolvedUsers.ContainsKey($Login)) {
        $encodedLogin = [Uri]::EscapeDataString($Login)
        $resolvedUsers[$Login] =
            Invoke-GitHubApi -Uri "https://api.github.com/users/$encodedLogin"
    }

    $resolvedUsers[$Login]
}

foreach ($login in $BypassUser) {
    $user = Resolve-GitHubUser -Login $login
    $bypassActors += @{
        actor_id    = $user.id
        actor_type  = 'User'
        bypass_mode = 'pull_request'
    }
}

$payload.bypass_actors = $bypassActors

if (-not $SkipEnvironments) {
    $environmentReviewers = @()

    foreach ($login in $EnvironmentReviewerUser) {
        $user = Resolve-GitHubUser -Login $login
        $environmentReviewers += @{
            type = 'User'
            id   = $user.id
        }
    }

    foreach ($teamReference in $EnvironmentReviewerTeam) {
        if ($teamReference -notmatch '^(?<organization>[^/]+)/(?<slug>[^/]+)$') {
            throw "Environment reviewer team must use the ORGANIZATION/SLUG format: $teamReference"
        }

        $organization = [Uri]::EscapeDataString($Matches.organization)
        $teamSlug = [Uri]::EscapeDataString($Matches.slug)
        $team = Invoke-GitHubApi `
            -Uri "https://api.github.com/orgs/$organization/teams/$teamSlug"
        $environmentReviewers += @{
            type = 'Team'
            id   = $team.id
        }
    }

    foreach ($environmentName in $Environment) {
        $requiresApproval = $environmentName -in $ApprovalEnvironment
        $encodedEnvironment = [Uri]::EscapeDataString($environmentName)
        $environmentPayload = @{
            wait_timer          = 0
            prevent_self_review = $requiresApproval
            reviewers           = if ($requiresApproval) {
                $environmentReviewers
            }
            else {
                @()
            }
        }

        Invoke-GitHubApi `
            -Uri "$apiBase/environments/$encodedEnvironment" `
            -Method Put `
            -Body $environmentPayload | Out-Null
        Write-Host "Configured environment `"$environmentName`"."
    }
}

$rulesets = @(
    Invoke-GitHubApi -Uri "$apiBase/rulesets?includes_parents=false"
)
$existing = $rulesets |
    Where-Object {
        $_.source_type -eq 'Repository' -and
        ($_.name -eq $Name -or ($Replace -and $_.name -eq $Replace))
    } |
    Select-Object -First 1

if ($existing) {
    $result = Invoke-GitHubApi `
        -Uri "$apiBase/rulesets/$($existing.id)" `
        -Method Put `
        -Body $payload
    Write-Host "Updated ruleset `"$($result.name)`" ($($result.id))."
}
else {
    $result = Invoke-GitHubApi `
        -Uri "$apiBase/rulesets" `
        -Method Post `
        -Body $payload
    Write-Host "Created ruleset `"$($result.name)`" ($($result.id))."
}

if ($DeleteClassicProtection) {
    $repositoryDetails = Invoke-GitHubApi -Uri $apiBase
    $protectedBranch = if ($Branch) { $Branch } else { $repositoryDetails.default_branch }
    $encodedBranch = [Uri]::EscapeDataString($protectedBranch)

    try {
        Invoke-GitHubApi `
            -Uri "$apiBase/branches/$encodedBranch/protection" `
            -Method Delete
        Write-Host "Deleted classic protection for `"$protectedBranch`"."
    }
    catch {
        $statusCode = [int] $_.Exception.Response.StatusCode
        if ($statusCode -eq 404) {
            Write-Host "No classic protection exists for `"$protectedBranch`"."
        }
        else {
            throw "Ruleset installed, but classic protection deletion failed: $($_.Exception.Message)"
        }
    }
}

Write-Host $result._links.html.href
