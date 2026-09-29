$ErrorActionPreference = "Stop"

Write-Host "Setting up Airlock Environment..." -ForegroundColor Cyan

# 1. Create Virtual Environment
if (!(Test-Path -Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# 2. Activate Virtual Environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
$activatePath = Join-Path -Path ".venv" -ChildPath "Scripts\Activate.ps1"
if (Test-Path $activatePath) {
    . $activatePath
} else {
    Write-Error "Failed to find venv activation script."
    exit 1
}

# 3. Install Requirements
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
pip install fastapi uvicorn

# 4. Fetch/Mock Models
Write-Host "Fetching models..." -ForegroundColor Yellow
$modelDir = "neolock_core\models"
if (!(Test-Path -Path $modelDir)) {
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
}

$classifierPath = Join-Path -Path $modelDir -ChildPath "classifier.onnx"
if (!(Test-Path -Path $classifierPath)) {
    Write-Host "Creating dummy classifier model for simulation..." -ForegroundColor Gray
    Set-Content -Path $classifierPath -Value "dummy_classifier_model_data"
}

$embedderPath = Join-Path -Path $modelDir -ChildPath "embedder.onnx"
if (!(Test-Path -Path $embedderPath)) {
    Write-Host "Creating dummy embedder model for simulation..." -ForegroundColor Gray
    Set-Content -Path $embedderPath -Value "dummy_embedder_model_data"
}

$tokenizerPath = Join-Path -Path $modelDir -ChildPath "tokenizer.json"
if (!(Test-Path -Path $tokenizerPath)) {
    Write-Host "Creating dummy tokenizer..." -ForegroundColor Gray
    Set-Content -Path $tokenizerPath -Value '{"version": "1.0", "model": {"type": "WordPiece", "vocab": {"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "[MASK]": 4}}}'
}

# 5. Build Context Binaries
Write-Host "Building context binaries (simulated)..." -ForegroundColor Yellow
$classifierCtxPath = Join-Path -Path $modelDir -ChildPath "classifier.ctx"
if (!(Test-Path -Path $classifierCtxPath)) {
    Set-Content -Path $classifierCtxPath -Value "dummy_ctx_binary"
}

# 6. Run System Doctor
Write-Host "Running System Doctor..." -ForegroundColor Yellow
python -m neolock_core.cli doctor

Write-Host "Installation Complete! You can now run the lab and dashboard." -ForegroundColor Green
Write-Host "  > python -m neolock_core.cli lab"
Write-Host "  > python -m neolock_core.cli bench"
Write-Host "  > python -m neolock_core.cli ui"
