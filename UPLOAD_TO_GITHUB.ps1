$ErrorActionPreference = "Stop"

$Owner = "ritikmoga"
$Repo = "secure-comm-firmware"
$FullRepo = "$Owner/$Repo"

Write-Host "Preparing to upload to https://github.com/$FullRepo" -ForegroundColor Cyan

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is not installed. Install Git for Windows, reopen PowerShell, and run this script again."
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "GitHub CLI is not installed." -ForegroundColor Yellow
    Write-Host "Install it with: winget install --id GitHub.cli" -ForegroundColor Yellow
    Write-Host "Then reopen PowerShell and run: gh auth login" -ForegroundColor Yellow
    exit 1
}

try {
    gh auth status | Out-Null
} catch {
    Write-Host "Sign in to GitHub in the prompt that follows." -ForegroundColor Yellow
    gh auth login --web --git-protocol https
}

if (-not (Test-Path ".git")) {
    git init -b main
}

git add .
if (-not (git diff --cached --quiet)) {
    git commit -m "Initial secure communication firmware project"
}

$repoExists = $false
try {
    gh repo view $FullRepo | Out-Null
    $repoExists = $true
} catch {
    $repoExists = $false
}

if ($repoExists) {
    Write-Host "Repository already exists; pushing to it." -ForegroundColor Cyan
    if (git remote get-url origin 2>$null) {
        git remote set-url origin "https://github.com/$FullRepo.git"
    } else {
        git remote add origin "https://github.com/$FullRepo.git"
    }
    git branch -M main
    git push -u origin main
} else {
    gh repo create $FullRepo --public --source . --remote origin --push `
        --description "ESP32-S3 secure communication firmware using mutual TLS, end-to-end encryption, replay protection, and signed OTA."
}

Write-Host "Upload complete: https://github.com/$FullRepo" -ForegroundColor Green
