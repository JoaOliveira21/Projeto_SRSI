# Análise de Vulnerabilidades Web e Mitigação com WAF ModSecurity

**Unidade Curricular:** Segurança em Redes e Sistemas de Informação  
**Instituição:** Iscte - Instituto Universitário de Lisboa  
**Ano Letivo:** 2026/2027  
**Docente:** Prof. Daniel Caçador  

**Autores:**
* Daniel Nunes — Nº 123547
* Guilherme Alves — Nº 122661
* João Oliveira — Nº 142584

---

## Descrição do Projeto

Este projeto analisa o impacto prático de vulnerabilidades Web críticas (**SQL Injection** e **Cross-Site Scripting**) e avalia experimentalmente a eficácia defensiva e o custo de desempenho do *Web Application Firewall* (**ModSecurity v3**) integrado em **Nginx** com o conjunto de regras **OWASP Core Rule Set (CRS 4.30.0)**, operando num ambiente virtualizado e isolado em **Docker**.

O trabalho encontra-se dividido em duas fases concluídas:
1. **Fase 1 (Teórica):** Enquadramento das vulnerabilidades do OWASP Top 10, arquitetura de 5 fases do ModSecurity v3, comparação de soluções WAF e definição do modelo matemático de avaliação.
2. **Fase 2 (Prática e Experimental):** Implementação do ambiente em Docker Compose, execução automatizada de conjuntos de ataque e tráfego legítimo, testes ofensivos com `sqlmap`, análise de registos JSON (`audit.log`), comparação entre *Paranoia Level 1*, *Paranoia Level 2* e *Tuning*, e *benchmarking* de latência ($\Delta L$) com Apache Benchmark (`ab`).

---

## Estrutura do Repositório

* **`docs/`** — Documentação e relatórios do projeto:
  * `Proposta_Projeto_SRSI_DanielNunes_GuilhermeAlves_JoaoOliveira.pdf` — Proposta inicial do projeto.
  * `Projeto_SRSI_Daniel_Nunes_Guilherme_Alves_Joao_Oliveira.pdf` e `src_latex/` — Relatório da Fase 1 (PDF e fonte LaTeX).
  * `Projeto_Pratico_SRSI_Daniel_Nunes_Guilherme_Alves_Joao_Oliveira.pdf` e `src_latex/` — Relatório da Fase 2 (PDF e fonte LaTeX).
  * `src_latex/` e `src_latex_fase2/` — Relatórios de ambas as fases (fonte LaTeX, figuras geradas).
* **`SRC/`** — Infraestrutura Docker, conjuntos de teste, scripts de avaliação e resultados (ver [SRC/README.md](SRC/README.md) para detalhes):
  * `docker-compose.yml` — Orquestra `dvwa` (`127.0.0.1:8081`), `proxy-base` (`127.0.0.1:8082`, Nginx sem WAF) e `waf` (`127.0.0.1:8080`, Nginx + ModSecurity v3 + OWASP CRS) na rede isolada `srsi_net`.
  * `.env` / `.env.example` — Parametrização do ModSecurity (`MODSEC_RULE_ENGINE`, `BLOCKING_PARANOIA`, `ANOMALY_INBOUND`, auditoria JSON).
  * `nginx/baseline.conf` — Configuração do *reverse proxy* de linha de base sem WAF.
  * `modsecurity/` — Regras personalizadas antes (`REQUEST-900-...`) e depois (`RESPONSE-999-...`) do CRS, incluindo a regra de *tuning* cirúrgico (`id:100200`) para PL2.
  * `datasets/` — `attacks.tsv` (28 vetores de SQLi *In-Band*, SQLi *Blind*, SQLi *Evasion*, XSS *Reflected*, XSS *Stored* e XSS *Evasion*) e `legitimate.tsv` (20 pedidos legítimos, incluindo 4 casos de fronteira).
  * `scripts/` — Automação em Python, PowerShell e Bash (`run_evaluation.py`, `run_benchmark.py`, `run_all.ps1`, `run_all.sh`).
  * `results/` — Resultados detalhados e resumos em CSV/JSON (`pl1/`, `pl2/`, `pl2_tuned/`, `sqlmap_base/`, `sqlmap_waf/`).
  * `logs/` — Registos estruturados de auditoria (`audit.log` em JSON, Fase 5 do ModSecurity).

---

## Resumo dos Resultados Experimentais

### Eficácia de Deteção (28 Ataques + 20 Pedidos Legítimos)

| Configuração | TP | FN | FP | TN | Precisão | Sensibilidade | Especificidade | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **OWASP CRS PL1 (Padrão)** | 28 | 0 | 0 | 20 | `1.0000` | `1.0000` | `1.0000` | `1.0000` |
| **OWASP CRS PL2** | 28 | 0 | 2 | 18 | `0.9333` | `1.0000` | `0.9000` | `0.9655` |
| **OWASP CRS PL2 + Tuning** | 28 | 0 | 0 | 20 | `1.0000` | `1.0000` | `1.0000` | `1.0000` |

* **Exploração `sqlmap`:** No *baseline* (`proxy-base`), o `sqlmap` identificou 4 técnicas de SQLi no parâmetro `id` (62 pedidos) e enumerou as bases de dados `dvwa` e `information_schema`. Com o WAF ativo, foi bloqueado com **377 respostas HTTP `403 Forbidden`**.
* **Falsos Positivos e *Tuning* em PL2:** Ao elevar para `BLOCKING_PARANOIA=2`, os casos legítimos `LEG-17` (`2 < 5`) e `LEG-18` (`Please select the union...`) foram bloqueados em `/vulnerabilities/xss_s/` pelas regras `942131`, `942200` e `942260`. A exclusão cirúrgica sobre `ARGS:mtxMessage` em `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` (`id:100200`) eliminou ambos os falsos positivos mantendo 100% de deteção.

### Impacto na Latência ($\Delta L = L_{\text{WAF}} - L_{\text{Base}}$, $N = 500$ pedidos)

| Perfil | Concorrência ($c$) | $L_{\text{Base}}$ (ms) | $L_{\text{WAF}}$ (ms) | $\Delta L$ (ms) | Sobrecarga | Base (RPS) | WAF (RPS) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **PL1** | 10 | 13.019 | 14.928 | +1.909 | +14.66% | 768.10 | 669.87 |
| **PL1** | 50 | 64.582 | 73.480 | +8.898 | +13.78% | 774.21 | 680.46 |
| **PL2** | 10 | 14.413 | 15.461 | +1.048 | +7.27% | 693.82 | 646.79 |
| **PL2** | 50 | 65.015 | 86.905 | +21.890 | +33.67% | 769.05 | 575.34 |

---

## Como Executar

A partir da pasta `SRC/`:

### Windows (PowerShell)
```powershell
cd SRC
.\scripts\run_all.ps1 -RunSqlmap
```

### Linux / macOS / WSL
```bash
cd SRC
chmod +x scripts/run_all.sh
./scripts/run_all.sh --sqlmap
```

Consulta o guia completo de utilização, testes manuais (`cURL`, `sqlmap`, `ab`) e limpeza do ambiente em **[SRC/README.md](SRC/README.md)**.
