# Análise de Vulnerabilidades Web e Mitigação com WAF ModSecurity

**Unidade Curricular:** Segurança em Redes e Sistemas de Informação 
**Instituição:** Iscte - Instituto Universitário de Lisboa  
**Ano Letivo:** 2026/2027  
**Alunos**:

* Daniel Nunes - Nº 123547
* Guilherme Alves - Nº 122661
* João Oliveira - Nº 142584

---

## Descrição do Projeto
Este projeto tem como objetivo analisar o impacto prático de vulnerabilidades Web críticas (especificamente **SQL Injection** e **Cross-Site Scripting**) e avaliar a eficácia defensiva do Web Application Firewall (**ModSecurity v3**) com o conjunto de regras **OWASP Core Rule Set (CRS)**, operando em ambiente virtualizado via Docker.

---

## Estrutura do Repositório
* **`/docs`**: Contém o relatório da Fase 1 em formato PDF e os respetivos ficheiros-fonte em LaTeX.
* **`/src`**: Configurações de infraestrutura, incluindo `docker-compose.yml`, ficheiros de configuração do Nginx e regras personalizadas do ModSecurity.

---

## Métricas de Avaliação Formal
O comportamento e eficácia do WAF serão quantificados através de métricas formais baseadas na matriz de confusão:
* **Precisão (Precision):** $\frac{TP}{TP + FP}$
* **Sensibilidade (Recall):** $\frac{TP}{TP + FN}$
* **Acurácia Balanceada (Balanced Accuracy):** $\frac{\text{Recall} + \text{Especificidade}}{2}$
* **Impacto de Latência ($\Delta L$):** Diferencial de tempo médio de resposta com o WAF ativo vs. inativo.

---

## Próximos Passos (Fase 2 - Prática)
1. Implementação do ambiente em contentores Docker (Nginx + ModSecurity v3 + DVWA).
2. Execução sistemática de ataques utilizando `sqlmap`, `Burp Suite` e scripts em `cURL`.
3. Análise dos ficheiros de auditoria (`audit.log`) do ModSecurity.
4. Benchmarking de desempenho através de `Apache Benchmark` (`ab`).