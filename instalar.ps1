# Argos - instalador de dependencias (Windows / PowerShell)
# -----------------------------------------------------------------------------
# O Argos.exe roda sozinho, mas as trilhas usam ferramentas externas. Este script
# confere o que falta e INSTALA, perguntando antes de cada uma. Alguns passos
# (WSL e certos pacotes) pedem administrador e, no caso do WSL, reinicio.
#
# Como rodar:  botao direito > "Executar com o PowerShell"
#   ou:        powershell -ExecutionPolicy Bypass -File instalar.ps1
# -----------------------------------------------------------------------------

function Confirmar($msg) { return ((Read-Host "$msg [s/N]") -match '^[sS]') }
function Tem($cmd) { return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue) }

Write-Host ""
Write-Host "=== Argos - conferindo dependencias ===" -ForegroundColor Cyan
Write-Host "Responda s (sim) para instalar, qualquer outra tecla para pular." -ForegroundColor DarkGray
Write-Host ""

if (-not (Tem winget)) {
    Write-Host "winget nao encontrado. Instale 'Instalador de Aplicativo' (App Installer) pela" -ForegroundColor Yellow
    Write-Host "Microsoft Store e rode este script de novo." -ForegroundColor Yellow
    exit 1
}

# Ferramentas que o winget instala. O 'id' e o pacote; o 'cmd' e como o Argos o acha no PATH.
$ferramentas = @(
    @{ nome = 'gitleaks (segredos no codigo)';      cmd = 'gitleaks';    id = 'Gitleaks.Gitleaks' },
    @{ nome = 'OSV-Scanner (dependencias)';          cmd = 'osv-scanner'; id = 'Google.OSVScanner' },
    @{ nome = 'Trivy (Dockerfile/compose)';          cmd = 'trivy';       id = 'AquaSecurity.Trivy' },
    @{ nome = 'Nmap (portas que escutam)';           cmd = 'nmap';        id = 'Insecure.Nmap' },
    @{ nome = 'GitHub CLI / gh (trava do ataque)';   cmd = 'gh';          id = 'GitHub.cli' },
    @{ nome = 'Ollama (IA local, opcional)';         cmd = 'ollama';      id = 'Ollama.Ollama' }
)

foreach ($f in $ferramentas) {
    if (Tem $f.cmd) { Write-Host ("  OK   " + $f.nome) -ForegroundColor Green; continue }
    if (Confirmar ("Instalar " + $f.nome + "?")) {
        winget install --id $f.id -e --accept-package-agreements --accept-source-agreements
    } else {
        Write-Host ("  pulado: " + $f.nome) -ForegroundColor DarkGray
    }
}

# pip-audit roda nativo no Windows, no mesmo Python.
Write-Host ""
if (Tem python) {
    if (Confirmar "Instalar pip-audit (CVEs de dependencias Python)?") {
        python -m pip install --upgrade pip-audit
    }
} else {
    Write-Host "  Python nao encontrado no PATH; pulei pip-audit." -ForegroundColor DarkGray
}

# semgrep no Windows roda melhor via WSL. Oferecemos instalar o WSL e, dentro
# dele, o semgrep. O WSL precisa de admin e de reinicio na primeira vez.
Write-Host ""
if (-not (Tem wsl)) {
    if (Confirmar "Instalar o WSL (Linux no Windows, usado pelo semgrep)? Precisa de admin e reinicio.") {
        Write-Host "  Abrindo instalacao do WSL como administrador..." -ForegroundColor Cyan
        Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-Command','wsl --install'
        Write-Host "  Depois de reiniciar, rode este script de novo para instalar o semgrep no WSL." -ForegroundColor Yellow
    }
} else {
    if (Confirmar "WSL ja existe. Instalar o semgrep DENTRO do WSL agora?") {
        wsl -e bash -lc "python3 -m pip install --user semgrep || sudo apt-get update && sudo apt-get install -y python3-pip && python3 -m pip install --user semgrep"
    }
}

Write-Host ""
Write-Host "=== Pronto. Abra o Argos.exe. ===" -ForegroundColor Cyan
Write-Host "O Argos pula sozinho a ferramenta que nao estiver instalada e diz qual falta." -ForegroundColor DarkGray
