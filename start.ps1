# CLOUDWATCH Startup Script
# Starts the FastAPI backend and React frontend dev server

Write-Host "Starting CLOUDWATCH..." -ForegroundColor Cyan

# Check for .env
if (-not (Test-Path "backend\.env")) {
    Write-Host "Warning: backend\.env not found. Copy backend\.env.example to backend\.env and add your ANTHROPIC_API_KEY" -ForegroundColor Yellow
}

# Start backend
Write-Host "Starting FastAPI backend on http://localhost:8000..." -ForegroundColor Green
$backend = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m uvicorn main:app --reload --port 8001" -PassThru

Start-Sleep -Seconds 2

# Start frontend
Write-Host "Starting React frontend on http://localhost:5173..." -ForegroundColor Green
$frontend = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev" -PassThru

Write-Host ""
Write-Host "CLOUDWATCH is running!" -ForegroundColor Cyan
Write-Host "Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "Backend API: http://localhost:8001" -ForegroundColor White
Write-Host "API Docs: http://localhost:8001/docs" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to stop..." -ForegroundColor Gray
Read-Host

$backend | Stop-Process -ErrorAction SilentlyContinue
$frontend | Stop-Process -ErrorAction SilentlyContinue
