# Render PlantUML diagrams (PowerShell)
# Usage: .\tools\render_uml.ps1

# Determine script and repo paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')

$toolsDir = Join-Path $repoRoot 'tools'
$plantumlJar = Join-Path $toolsDir 'plantuml.jar'
$umlSrc = Join-Path $repoRoot 'docs\uml'
$outDir = Join-Path $repoRoot 'docs\images\uml'

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

# Ensure Java available
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host 'ERROR: java not found on PATH. Install OpenJDK or add java to PATH.' -ForegroundColor Red
    exit 1
}

# Download plantuml.jar if missing
if (-not (Test-Path $plantumlJar)) {
    Write-Host 'plantuml.jar not found; attempting to download...'
    try {
        $url = 'https://github.com/plantuml/plantuml/releases/latest/download/plantuml.jar'
        Invoke-WebRequest -Uri $url -OutFile $plantumlJar -ErrorAction Stop
        Write-Host "Downloaded plantuml.jar to $plantumlJar"
    } catch {
        Write-Host 'Failed to download plantuml.jar. Please download it manually from https://github.com/plantuml/plantuml/releases and place it in the tools folder.' -ForegroundColor Yellow
        exit 1
    }
}

# Render PNG and SVG using plantuml.jar
Write-Host 'Rendering PNG...'
& java -jar $plantumlJar -tpng -o $outDir (Join-Path $umlSrc '*.puml')

Write-Host 'Rendering SVG...'
& java -jar $plantumlJar -tsvg -o $outDir (Join-Path $umlSrc '*.puml')

Write-Host "Done. Files written to: $outDir" -ForegroundColor Green
