<#
.SYNOPSIS
Executa o pipeline completo da Fase 2 (Pratica) no computador pessoal (Windows PowerShell).

.DESCRIPTION
1. Garante que os contentores Docker estao ativos (dvwa, proxy-base, waf).
2. Corre a avaliacao de ataques + trafego legitimo e calcula a Matriz de Confusao (run_evaluation.py).
3. Corre o benchmark de latencia com Apache Benchmark (run_benchmark.py) para calcular Delta L.
4. Opcionalmente, executa testes automatizados de SQLi com sqlmap via Docker (-RunSqlmap).
#>

param(
    [switch]$RunSqlmap,
    [int]$BenchRequests = 500,
    [string]$BenchConcurrency = "10,50"
)

$ErrorActionPreference = "Stop"
$SrcDir = Split-Path -Parent $PSScriptRoot
Set-Location $SrcDir

function Invoke-PythonScript {
    param([string[]]$ScriptArgs)
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }

    if ($py -and $py.Source -notmatch "WindowsApps") {
        & $py.Source @ScriptArgs
        return
    }

    Write-Host "[*] Python local nao encontrado; a usar contentor python:3.12-alpine..." -ForegroundColor Yellow
    $dockerArgs = @("run", "--rm", "--network", "srsi_net", "-v", "${SrcDir}:/work", "-w", "/work", "python:3.12-alpine", "python") + $ScriptArgs
    & docker @dockerArgs
}

Write-Host "=== 1. A verificar/iniciar contentores Docker ===" -ForegroundColor Cyan
docker compose up -d
Start-Sleep -Seconds 4

$hasLocalPython = (Get-Command python -ErrorAction SilentlyContinue) -and ((Get-Command python).Source -notmatch "WindowsApps")

Write-Host "`n=== 2. A executar avaliacao de detecao e Matriz de Confusao ===" -ForegroundColor Cyan
if ($hasLocalPython) {
    Invoke-PythonScript -ScriptArgs @("scripts/run_evaluation.py", "--waf-url", "http://127.0.0.1:8080", "--baseline-url", "http://127.0.0.1:8082")
} else {
    Invoke-PythonScript -ScriptArgs @("scripts/run_evaluation.py", "--waf-url", "http://waf:8080", "--baseline-url", "http://proxy-base:80")
}

Write-Host "`n=== 3. A executar Apache Benchmark (Delta L) ===" -ForegroundColor Cyan
if ($hasLocalPython) {
    Invoke-PythonScript -ScriptArgs @("scripts/run_benchmark.py", "--requests", "$BenchRequests", "--concurrency", "$BenchConcurrency")
} else {
    Write-Host "[*] A obter cookie de sessao via contentor..." -ForegroundColor Yellow
    $baseCookie = docker run --rm --network srsi_net -v "${SrcDir}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://proxy-base:80 --print-cookie
    $wafCookie = docker run --rm --network srsi_net -v "${SrcDir}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://waf:8080 --print-cookie

    foreach ($c in $BenchConcurrency.Split(",")) {
        $conc = $c.Trim()
        Write-Host "`n--- Baseline (Nginx sem WAF) c=$conc n=$BenchRequests ---"
        docker run --rm --network srsi_net httpd:alpine sh -c "apk add --no-cache apache2-utils >/dev/null && ab -n $BenchRequests -c $conc -C '$baseCookie' 'http://proxy-base:80/vulnerabilities/sqli/?id=1&Submit=Submit'"
        Write-Host "`n--- WAF (Nginx + ModSecurity + CRS) c=$conc n=$BenchRequests ---"
        docker run --rm --network srsi_net httpd:alpine sh -c "apk add --no-cache apache2-utils >/dev/null && ab -n $BenchRequests -c $conc -C '$wafCookie' 'http://waf:8080/vulnerabilities/sqli/?id=1&Submit=Submit'"
    }
}

if ($RunSqlmap) {
    Write-Host "`n=== 4. A executar sqlmap contra Baseline vs WAF ===" -ForegroundColor Cyan
    if (-not $hasLocalPython) {
        $baseCookie = (docker run --rm --network srsi_net -v "${SrcDir}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://proxy-base:80 --print-cookie) | Select-Object -Last 1
        $wafCookie = (docker run --rm --network srsi_net -v "${SrcDir}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://waf:8080 --print-cookie) | Select-Object -Last 1
    } else {
        $baseCookie = (python scripts/run_evaluation.py --waf-url http://127.0.0.1:8082 --print-cookie) | Select-Object -Last 1
        $wafCookie = (python scripts/run_evaluation.py --waf-url http://127.0.0.1:8080 --print-cookie) | Select-Object -Last 1
    }

    Write-Host "[*] sqlmap (In-Band) SEM WAF (Baseline)..."
    docker run --rm --network srsi_net -v "${SrcDir}/results/sqlmap_base:/root/.local/share/sqlmap" parrotsec/sqlmap `
        -u "http://proxy-base:80/vulnerabilities/sqli/?id=1&Submit=Submit" `
        --cookie="$baseCookie" -p id --batch --dbs --flush-session --level=2 --risk=1

    Write-Host "[*] sqlmap (In-Band) COM WAF (ModSecurity + CRS)..."
    docker run --rm --network srsi_net -v "${SrcDir}/results/sqlmap_waf:/root/.local/share/sqlmap" parrotsec/sqlmap `
        -u "http://waf:8080/vulnerabilities/sqli/?id=1&Submit=Submit" `
        --cookie="$wafCookie" -p id --batch --dbs --flush-session --level=2 --risk=1
}

Write-Host "`n[+] Concluido! Verifica a pasta SRC/results e SRC/logs/audit.log." -ForegroundColor Green
