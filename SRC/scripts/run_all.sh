#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR"

RUN_SQLMAP="${1:-}"
BENCH_REQUESTS="${BENCH_REQUESTS:-500}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-10,50}"

echo "=== 1. A verificar/iniciar contentores Docker ==="
docker compose up -d
sleep 4

echo "=== 2. A executar avaliacao de detecao e Matriz de Confusao ==="
if command -v python3 >/dev/null 2>&1; then
  python3 scripts/run_evaluation.py --waf-url http://127.0.0.1:8080 --baseline-url http://127.0.0.1:8082
  echo "=== 3. A executar Apache Benchmark (Delta L) ==="
  python3 scripts/run_benchmark.py --requests "$BENCH_REQUESTS" --concurrency "$BENCH_CONCURRENCY"
else
  docker run --rm --network srsi_net -v "${SRC_DIR}:/work" -w /work python:3.12-alpine \
    python scripts/run_evaluation.py --waf-url http://waf:8080 --baseline-url http://proxy-base:80
fi

if [[ "$RUN_SQLMAP" == "--sqlmap" ]]; then
  echo "=== 4. A executar sqlmap contra Baseline vs WAF ==="
  BASE_COOKIE=$(docker run --rm --network srsi_net -v "${SRC_DIR}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://proxy-base:80 --print-cookie)
  WAF_COOKIE=$(docker run --rm --network srsi_net -v "${SRC_DIR}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://waf:8080 --print-cookie)

  docker run --rm --network srsi_net -v "${SRC_DIR}/results/sqlmap_base:/root/.local/share/sqlmap" parrotsec/sqlmap \
    -u "http://proxy-base:80/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="$BASE_COOKIE" --batch --dbs --level=2 --risk=1

  docker run --rm --network srsi_net -v "${SRC_DIR}/results/sqlmap_waf:/root/.local/share/sqlmap" parrotsec/sqlmap \
    -u "http://waf:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="$WAF_COOKIE" --batch --dbs --level=2 --risk=1
fi

echo "[+] Concluido! Verifica a pasta SRC/results e SRC/logs/audit.log."
