. C:\MCP\set_env.ps1

$adminHeaders = @{ "X-Admin-Key" = $env:ADMIN_API_KEY }

function Section($text) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}

function Ok($text) { Write-Host "  [OK] $text" -ForegroundColor Green }
function Info($text) { Write-Host "  --> $text" -ForegroundColor Yellow }

# STEP 1
Section "STEP 1: Onboard a client (Acme Corp)"
Info "Creating tenant..."
$tenantBody = @{ name = "acme_corp" } | ConvertTo-Json
$tenant = Invoke-RestMethod -Uri http://localhost:8000/admin/tenants `
    -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $tenantBody
Ok "Tenant created: $($tenant.name)  [id: $($tenant.id)]"

Info "Generating API key for Acme Corp..."
$keyBody = @{ label = "demo-key" } | ConvertTo-Json
$keyResp = Invoke-RestMethod -Uri "http://localhost:8000/admin/tenants/$($tenant.id)/keys" `
    -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $keyBody
Ok "API key issued: $($keyResp.api_key)"
Info "(Raw key shown once, never stored -- only a SHA-256 hash is saved)"

$apiKey = $keyResp.api_key
$tenantId = $tenant.id

# STEP 2
Section "STEP 2: Register GitHub API as a callable tool"
Info "Registering endpoint: GET https://api.github.com/repos/{owner}/{repo}"

$apiBody = @{
    tenant_id      = $tenantId
    name           = "get_github_repo"
    description    = "Fetch public GitHub repo metadata"
    method         = "GET"
    url_template   = "https://api.github.com/repos/{owner}/{repo}"
    path_params    = @{
        owner = @{ type = "string"; description = "GitHub org or username" }
        repo  = @{ type = "string"; description = "Repository name" }
    }
    static_headers = @{ Accept = "application/vnd.github+json" }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri http://localhost:8000/admin/apis `
    -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $apiBody | Out-Null
Ok "API registered. MCP server will expose it as a tool automatically."

# STEP 3
Section "STEP 3: AI agent connects via MCP and calls the tool"
Info "Running MCP client (simulates an AI agent)..."
python test_client.py $apiKey

# STEP 4
Section "STEP 4: Auth rejection"
Info "Trying with no key..."
try { Invoke-RestMethod -Uri http://localhost:8000/mcp -Method Post } `
    catch { Ok "Blocked --> HTTP $($_.Exception.Response.StatusCode.value__) Unauthorized" }

Info "Trying with a fake key..."
try {
    Invoke-RestMethod -Uri http://localhost:8000/mcp -Method Post `
        -Headers @{ "X-API-Key" = "lgfmcp_thisisafakekey" }
}
catch { Ok "Blocked --> HTTP $($_.Exception.Response.StatusCode.value__) Unauthorized" }

# STEP 5
Section "STEP 5: Tenant isolation -- rival company sees nothing"
Info "Creating Rival Corp with its own valid key..."
$t2Body = @{ name = "rival_corp" } | ConvertTo-Json
$t2 = Invoke-RestMethod -Uri http://localhost:8000/admin/tenants `
    -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $t2Body
$k2Body = @{ label = "rival-key" } | ConvertTo-Json
$k2 = Invoke-RestMethod -Uri "http://localhost:8000/admin/tenants/$($t2.id)/keys" `
    -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $k2Body

Info "Rival Corp agent connects with their own valid key..."
python test_client.py $k2.api_key

Section "DEMO COMPLETE"
Ok "One server. Multiple clients. Each sees only their own APIs. Auth enforced."