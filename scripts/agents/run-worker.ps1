[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("claude", "codex")]
    [string]$Engine,

    [ValidateSet("claude", "codex")]
    [string]$OrchestratorHost,

    [Parameter(Mandatory = $true)]
    [string]$Plan,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvironmentValueOrDefault {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$DefaultValue
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }

    return $value.Trim()
}

function Get-OrchestratorHostEngine {
    param(
        [string]$DeclaredHost
    )

    $isCodexHost = -not [string]::IsNullOrWhiteSpace($env:CODEX_THREAD_ID)
    $isClaudeHost = -not [string]::IsNullOrWhiteSpace($env:CLAUDECODE) -or
        -not [string]::IsNullOrWhiteSpace($env:CLAUDE_CODE_ENTRYPOINT)

    if ($isCodexHost -and $isClaudeHost) {
        throw "Cannot select a worker engine: both Codex and Claude Code host markers are present."
    }

    $detectedHost = $null
    if ($isCodexHost) {
        $detectedHost = "codex"
    }
    elseif ($isClaudeHost) {
        $detectedHost = "claude"
    }

    if ($null -ne $detectedHost) {
        if (-not [string]::IsNullOrWhiteSpace($DeclaredHost) -and $DeclaredHost -ne $detectedHost) {
            throw "OrchestratorHost '$DeclaredHost' conflicts with detected host '$detectedHost'."
        }

        return $detectedHost
    }

    if ([string]::IsNullOrWhiteSpace($DeclaredHost)) {
        throw "Cannot determine the orchestrator host. Run from Claude Code or Codex, or pass -OrchestratorHost claude|codex for non-interactive automation."
    }

    return $DeclaredHost
}

function Assert-WorkerAliasIsAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Alias,

        [Parameter(Mandatory = $true)]
        [string]$Engine
    )

    $headers = @{ Authorization = "Bearer $ApiKey" }
    try {
        $modelsResponse = Invoke-RestMethod `
            -Uri "$BaseUrl/v1/models" `
            -Headers $headers `
            -Method Get `
            -TimeoutSec 15 `
            -ErrorAction Stop
    }
    catch {
        throw "Could not verify worker alias '$Alias' using $BaseUrl/v1/models: $($_.Exception.Message)"
    }

    $modelIds = @($modelsResponse.data | ForEach-Object { $_.id })
    if ($Alias -notin $modelIds) {
        throw "Worker alias '$Alias' for engine '$Engine' is not published by 9router. Create the alias in 9router or explicitly set the matching NINEROUTER_*_ALIAS; do not fall back to a provider-prefixed model."
    }
}

function ConvertTo-TomlString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path.TrimEnd([char[]]@(92, 47))

if (-not (Test-Path -LiteralPath $Plan -PathType Leaf)) {
    throw "Plan file does not exist: $Plan"
}

$resolvedPlan = (Resolve-Path -LiteralPath $Plan).Path
$repoPrefix = $repoRoot + [System.IO.Path]::DirectorySeparatorChar
$isRepoRoot = $resolvedPlan.Equals($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)
$isInsideRepo = $resolvedPlan.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)
if (-not ($isRepoRoot -or $isInsideRepo)) {
    throw "Plan must be inside the repository: $resolvedPlan"
}

$hostEngine = Get-OrchestratorHostEngine -DeclaredHost $OrchestratorHost
if ($Engine -ne $hostEngine) {
    throw "Worker engine '$Engine' is not allowed from a '$hostEngine' orchestrator session. Use -Engine $hostEngine."
}

$relativePlan = $resolvedPlan.Substring($repoPrefix.Length).Replace('\', '/')
$planStem = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPlan)
$resolvedReport = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedPlan)) "REPORT-$planStem.md"
$relativeReport = $resolvedReport.Substring($repoPrefix.Length).Replace('\', '/')

$baseUrl = Get-EnvironmentValueOrDefault `
    -Name "NINEROUTER_BASE_URL" `
    -DefaultValue "http://192.168.21.30:20128"
$baseUrl = $baseUrl.TrimEnd('/')
if ($baseUrl.EndsWith("/v1", [System.StringComparison]::OrdinalIgnoreCase)) {
    $baseUrl = $baseUrl.Substring(0, $baseUrl.Length - 3).TrimEnd('/')
}

$baseUri = $null
$isAbsoluteUri = [System.Uri]::TryCreate($baseUrl, [System.UriKind]::Absolute, [ref]$baseUri)
if (-not $isAbsoluteUri -or $baseUri.Scheme -notin @("http", "https")) {
    throw "NINEROUTER_BASE_URL must be an absolute HTTP(S) URL."
}

$claudeAlias = Get-EnvironmentValueOrDefault `
    -Name "NINEROUTER_CLAUDE_ALIAS" `
    -DefaultValue "api-combo"
$codexAlias = Get-EnvironmentValueOrDefault `
    -Name "NINEROUTER_CODEX_ALIAS" `
    -DefaultValue "api-codex-combo"
$codexEndpoint = "$baseUrl/v1"

$prompt = @"
Read $relativePlan and carry it out.

Before starting work, wait for MCP servers to finish connecting (call WaitForMcpServers or
an equivalent readiness tool if one is available), then check whether mcp__serena__*,
mcp__codebase-memory-mcp__*, and mcp__semble__search are present. Some MCP servers connect
slower than the first turn, so a tool that is missing on the very first check may still
become available after waiting. Prefer these over raw Read/Grep/Edit for non-trivial code
navigation and editing: mcp__serena__* for precise symbol-level find/edit,
mcp__codebase-memory-mcp__* for call-graph/architecture queries, mcp__semble__search for
conceptual code search. Fall back to Read/Grep/Edit when the MCP tools are unavailable or
unsuited to the task.

Rules:
- Work only within the scope authorized by the plan and preserve unrelated user changes.
- Run the focused tests required by the plan after each change.
- Commit completed work locally with selective staging only; never use git add -A.
- When complete or blocked, write $relativeReport with changed files, test results, and blockers.
- Do not push and do not use gh. This also covers GitHub MCP tools: never call
  mcp__github__push_files, mcp__github__create_pull_request, mcp__github__merge_pull_request,
  mcp__github__create_or_update_file, mcp__github__delete_file, mcp__github__create_branch,
  mcp__github__create_repository, mcp__github__fork_repository, mcp__github__update_pull_request,
  mcp__github__update_pull_request_branch, or any other GitHub MCP tool that writes to the
  remote repository.
"@

if ($DryRun) {
    Write-Output "dry_run: true"
    Write-Output "orchestrator_host: $hostEngine"
    Write-Output "engine: $Engine"
    Write-Output "plan: $relativePlan"
    Write-Output "report: $relativeReport"

    if ($Engine -eq "claude") {
        Write-Output "alias: $claudeAlias"
        Write-Output "endpoint: $baseUrl"
        Write-Output "main_model: $claudeAlias"
        Write-Output "small_fast_model: $claudeAlias"
        Write-Output "command: claude -p <generated-prompt> --dangerously-skip-permissions --disallowedTools Bash(git push:*) Bash(gh:*) mcp__github__push_files mcp__github__create_pull_request mcp__github__merge_pull_request [+9 more mcp__github__* write tools]"
    }
    else {
        Write-Output "alias: $codexAlias"
        Write-Output "endpoint: $codexEndpoint"
        Write-Output "provider: ninerouter"
        Write-Output "wire_api: responses"
        Write-Output "sandbox: workspace-write"
        Write-Output "sandbox_workspace_write.network_access: false"
        Write-Output "shell_environment_policy.ignore_default_excludes: false"
        Write-Output "shell_environment_policy.exclude: NINEROUTER_API_KEY, ANTHROPIC_*, CODEX_API_KEY"
        Write-Output "command: codex exec --sandbox workspace-write --ephemeral --model $codexAlias <generated-prompt>"
    }

    exit 0
}

$apiKey = [Environment]::GetEnvironmentVariable("NINEROUTER_API_KEY")
if ([string]::IsNullOrWhiteSpace($apiKey)) {
    throw "NINEROUTER_API_KEY is required unless -DryRun is used."
}

$selectedAlias = if ($Engine -eq "claude") { $claudeAlias } else { $codexAlias }
Assert-WorkerAliasIsAvailable `
    -BaseUrl $baseUrl `
    -ApiKey $apiKey `
    -Alias $selectedAlias `
    -Engine $Engine

$workerExitCode = 1
Push-Location -LiteralPath $repoRoot
try {
    if ($Engine -eq "claude") {
        if (-not (Get-Command -Name "claude" -ErrorAction SilentlyContinue)) {
            throw "Claude Code CLI was not found on PATH."
        }

        $env:ANTHROPIC_BASE_URL = $baseUrl
        $env:ANTHROPIC_AUTH_TOKEN = $apiKey
        $env:ANTHROPIC_MODEL = $claudeAlias
        $env:ANTHROPIC_SMALL_FAST_MODEL = $claudeAlias

        $disallowedTools = @(
            "Bash(git push:*)",
            "Bash(gh:*)",
            "mcp__github__push_files",
            "mcp__github__create_pull_request",
            "mcp__github__merge_pull_request",
            "mcp__github__create_or_update_file",
            "mcp__github__delete_file",
            "mcp__github__create_branch",
            "mcp__github__create_repository",
            "mcp__github__fork_repository",
            "mcp__github__update_pull_request",
            "mcp__github__update_pull_request_branch",
            "mcp__github__issue_write",
            "mcp__github__sub_issue_write",
            "mcp__github__pull_request_review_write",
            "mcp__github__add_comment_to_pending_review",
            "mcp__github__add_issue_comment",
            "mcp__github__add_reply_to_pull_request_comment",
            "mcp__github__request_copilot_review"
        )

        & claude -p $prompt `
            --dangerously-skip-permissions `
            --disallowedTools @disallowedTools
        $workerExitCode = $LASTEXITCODE
    }
    else {
        if (-not (Get-Command -Name "codex" -ErrorAction SilentlyContinue)) {
            throw "Codex CLI was not found on PATH."
        }

        $tomlEndpoint = ConvertTo-TomlString -Value $codexEndpoint
        $codexArguments = @(
            "exec",
            "--sandbox", "workspace-write",
            "--ephemeral",
            "--model", $codexAlias,
            "--config", 'model_provider="ninerouter"',
            "--config", 'model_providers.ninerouter.name="9router"',
            "--config", "model_providers.ninerouter.base_url=$tomlEndpoint",
            "--config", 'model_providers.ninerouter.wire_api="responses"',
            "--config", 'model_providers.ninerouter.env_key="NINEROUTER_API_KEY"',
            "--config", 'sandbox_workspace_write.network_access=false',
            "--config", 'shell_environment_policy.ignore_default_excludes=false',
            "--config", "shell_environment_policy.exclude=['NINEROUTER_API_KEY','ANTHROPIC_*','CODEX_API_KEY']",
            $prompt
        )

        & codex @codexArguments
        $workerExitCode = $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

exit $workerExitCode
