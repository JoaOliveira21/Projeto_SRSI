# Fase 2 (Prática) — Infraestrutura Docker, Testes de Ataque e Benchmarking

Esta pasta contém todo o ambiente virtualizado e os scripts necessários para executar a parte prática descrita na **Secção 4** e **Secção 5** do relatório.

> **Nota de segurança:** Todas as portas publicadas em `docker-compose.yml` estão restringidas a `127.0.0.1` (apenas acesso local) para não expor a DVWA na rede local. Recomenda-se executar este ambiente num **computador pessoal** ou VM dedicada.

---

## 1. Estrutura da Pasta `SRC/`

* [`docker-compose.yml`](docker-compose.yml) — Orquestra 3 contentores na rede `srsi_net`:
  * **`dvwa`** (`vulnerables/web-dvwa`) em `http://127.0.0.1:8081` (acesso direto opcional).
  * **`proxy-base`** (`nginx:alpine`) em `http://127.0.0.1:8082` — *Reverse Proxy* Nginx **sem WAF** (para *baseline* de exploração e medição de $L_{\text{Base}}$).
  * **`waf`** (`owasp/modsecurity-crs:nginx`) em `http://127.0.0.1:8080` — *Reverse Proxy* Nginx **com ModSecurity v3 + OWASP CRS** (para medição de deteção e $L_{\text{WAF}}$).
* [`.env`](.env) / [`.env.example`](.env.example) — Variáveis do ModSecurity (`MODSEC_RULE_ENGINE`, `BLOCKING_PARANOIA`, `ANOMALY_INBOUND`, `MODSEC_AUDIT_LOG`, etc.).
* [`nginx/baseline.conf`](nginx/baseline.conf) — Configuração do Nginx *baseline* sem WAF.
* [`modsecurity/`](modsecurity/) — Ficheiros de regras personalizadas executadas antes (`REQUEST-900-...`) e depois (`RESPONSE-999-...`) do OWASP CRS.
* [`datasets/attacks.tsv`](datasets/attacks.tsv) — 28 *payloads* de ataque (SQLi In-Band, SQLi Blind, SQLi Evasion, XSS Reflected, XSS Stored, XSS Evasion).
* [`datasets/legitimate.tsv`](datasets/legitimate.tsv) — 20 pedidos legítimos (incluindo casos de fronteira com texto normal/apóstrofos/símbolos para medir *Falsos Positivos*).
* [`scripts/`](scripts/) — Scripts de avaliação automatizada, benchmark com `ab` e wrapper PowerShell/Bash.
* `logs/` — Onde é gravado `audit.log` em formato JSON (Fase 5 do ModSecurity).
* `results/` — Onde são guardados os ficheiros CSV/JSON com a Matriz de Confusão, métricas e latência ($\Delta L$).

---

## 2. Arranque Rápido (Computador Pessoal)

Abrir um terminal na pasta `SRC/`:

```powershell
# 1. Subir os contentores (DVWA + Proxy Base + WAF ModSecurity)
docker compose up -d

# 2. Verificar estado dos contentores
docker compose ps
```

*(O script de avaliação inicializa automaticamente a base de dados da DVWA via `/setup.php`, faz login com `admin`/`password` e define o nível de segurança `low`. Se quiseres aceder manualmente no browser, abre `http://127.0.0.1:8080` e clica em **Create / Reset Database**.)*

---

## 3. Executar Avaliação Completa (Matriz de Confusão + Benchmark)

### Windows (PowerShell)
```powershell
cd SRC
.\scripts\run_all.ps1
```
Para incluir também o teste automático com **`sqlmap`** via Docker:
```powershell
.\scripts\run_all.ps1 -RunSqlmap
```

### Linux / macOS / WSL
```bash
cd SRC
chmod +x scripts/run_all.sh
./scripts/run_all.sh          # ou ./scripts/run_all.sh --sqlmap
```

### O que é gerado em `SRC/results/`
* `detailed_results.csv` — Resultado pedido-a-pedido (`TP`, `FP`, `TN`, `FN`), código HTTP no Baseline vs. WAF e latência individual.
* `metrics_summary.json` — Matriz de confusão, **Precisão**, **Sensibilidade (Recall)**, **F1-Score**, **Especificidade**, **Acurácia Balanceada (BA)**, resultados por categoria e resumo das regras CRS mais ativadas em `logs/audit.log`.
* `latency_benchmark.csv` / `latency_benchmark.json` — Resultados do **Apache Benchmark (`ab`)** com $L_{\text{Base}}$, $L_{\text{WAF}}$, $\Delta L = L_{\text{WAF}} - L_{\text{Base}}$, RPS e percentis (`p95`).

---

## 4. Testes Manuais com `cURL`, `sqlmap`, `ab` e `OWASP ZAP` / `Burp Suite`

Primeiro, obtém um cookie de sessão válido da DVWA:
```powershell
python scripts/run_evaluation.py --waf-url http://127.0.0.1:8080 --print-cookie
```
*(Sem Python local, podes usar `docker run --rm --network srsi_net -v "${PWD}:/work" -w /work python:3.12-alpine python scripts/run_evaluation.py --waf-url http://waf:8080 --print-cookie`.)*

### Exemplo com `cURL` (Baseline vs. WAF)
```powershell
# Sem WAF (deve devolver HTTP 200 e expor dados)
curl.exe -i -b "PHPSESSID=<TEU_COOKIE>; security=low" "http://127.0.0.1:8082/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit"

# Com WAF (deve devolver HTTP 403 Forbidden)
curl.exe -i -b "PHPSESSID=<TEU_COOKIE>; security=low" "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit"
```

### Exemplo com `sqlmap` (via Docker)
```powershell
# SQLi In-Band com WAF ativo (deve ser bloqueado / detetar protecao WAF)
docker run --rm --network srsi_net parrotsec/sqlmap -u "http://waf:8080/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=<TEU_COOKIE>; security=low" --batch --dbs

# SQLi Blind sem WAF (Baseline)
docker run --rm --network srsi_net parrotsec/sqlmap -u "http://proxy-base:80/vulnerabilities/sqli_blind/?id=1&Submit=Submit" --cookie="PHPSESSID=<TEU_COOKIE>; security=low" --batch --current-db
```

### Exemplo com `OWASP ZAP` / `Burp Suite`
1. Configura o browser para usar o proxy do **Burp Suite** (`127.0.0.1:8080` — se usares Burp na porta `8080`, muda a porta do WAF no `docker-compose.yml` para `127.0.0.1:8083:8080` para não haver conflito de portas) ou abre o browser integrado do **OWASP ZAP**.
2. Aponta para `http://127.0.0.1:8082` (sem WAF) e `http://127.0.0.1:8080` (com WAF) para capturar pedidos, fazer *fuzzing* de *payloads* e comparar os alertas gerados.

---

## 5. Experiência Extra Recomendada para o Relatório: *Paranoia Levels* e *Tuning*

Para ilustrar experimentalmente o compromisso entre **deteção vs. falsos positivos** discutido na **Secção 3.2** do relatório:
1. Corre a avaliação com `BLOCKING_PARANOIA=1` (no `.env`) e guarda os resultados.
2. Altera `BLOCKING_PARANOIA=2` (ou `3`) no ficheiro `.env`, reinicia apenas o WAF:
   ```powershell
   docker compose up -d waf
   ```
   e volta a correr `run_evaluation.py` (guardando para `--results-dir results/pl2`). Observa se algum pedido em `legitimate.tsv` (ex.: `LEG-17`, `LEG-18`, `LEG-19`) passa a dar `FP` (`403`) e se algum ataque de evasão (`ATK-12` a `ATK-15`, `ATK-24` a `ATK-28`) passa de `FN` a `TP`.
3. Inspeciona as regras que dispararam em `logs/audit.log` e testa uma regra de afinação em `modsecurity/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` para eliminar os falsos positivos mantendo a deteção!

---

## 6. Parar e Limpar o Ambiente
```powershell
docker compose down -v
```
