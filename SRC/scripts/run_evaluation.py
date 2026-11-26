#!/usr/bin/env python3
"""
Avaliacao sistematica de eficacia do WAF ModSecurity v3 + OWASP CRS contra DVWA.

Executa os conjuntos de ataques (datasets/attacks.tsv) e trafego legitimo
(datasets/legitimate.tsv), valida a linha de base sem WAF (opcional),
calcula a Matriz de Confusao e metricas formais da Seccao 4.1 do relatorio,
e resume os eventos registados em logs/audit.log.
"""

from __future__ import annotations

import argparse
import csv
import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
DEFAULT_ATTACKS = SRC_DIR / "datasets" / "attacks.tsv"
DEFAULT_LEGIT = SRC_DIR / "datasets" / "legitimate.tsv"
DEFAULT_AUDIT_LOG = SRC_DIR / "logs" / "audit.log"
DEFAULT_RESULTS_DIR = SRC_DIR / "results"


class DvwaSession:
    """Gere autenticacao, inicializacao da BD e nivel de seguranca na DVWA."""

    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

    def _request(
        self,
        path: str,
        method: str = "GET",
        data: dict[str, str] | None = None,
    ) -> tuple[int, str, str, float]:
        url = f"{self.base_url}{path}"
        encoded_data = None
        headers = {"User-Agent": "SRSI-Evaluator/1.0"}

        if method.upper() == "POST" and data is not None:
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(
            url, data=encoded_data, headers=headers, method=method.upper()
        )
        t0 = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return resp.status, resp.geturl(), body, elapsed_ms
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return err.code, err.geturl(), body, elapsed_ms

    @staticmethod
    def _extract_user_token(html: str) -> str | None:
        patterns = [
            r"name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"]",
            r"value=['\"]([^'\"]+)['\"][^>]*name=['\"]user_token['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _set_cookie(self, name: str, value: str) -> None:
        parsed = urllib.parse.urlparse(self.base_url)
        domain = parsed.hostname or "localhost"
        cookie = http.cookiejar.Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=False,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
        )
        self.cookie_jar.set_cookie(cookie)

    def get_phpsessid(self) -> str:
        for cookie in self.cookie_jar:
            if cookie.name == "PHPSESSID":
                return cookie.value
        return ""

    @staticmethod
    def _login_succeeded(url: str, html: str) -> bool:
        return (
            "Login failed" not in html
            and "setup.php" not in url
            and "Logout" in html
        )

    def _initialize_db(self) -> None:
        _, _, setup_body, _ = self._request("/setup.php", "GET")
        setup_token = self._extract_user_token(setup_body)
        setup_payload = {"create_db": "Create / Reset Database"}
        if setup_token:
            setup_payload["user_token"] = setup_token
        self._request("/setup.php", "POST", setup_payload)

    def ensure_ready(self, username: str = "admin", password: str = "password") -> str:
        """Inicializa a BD se necessario, faz login e define security=low."""
        status, final_url, body = 0, "", ""
        last_err: Exception | None = None
        for _ in range(15):
            try:
                status, final_url, body, _ = self._request("/login.php", "GET")
                if status < 500 and "Unable to connect to the database" not in body:
                    last_err = None
                    break
            except (urllib.error.URLError, ConnectionError, TimeoutError) as err:
                last_err = err
            time.sleep(2)

        if last_err is not None:
            raise RuntimeError(
                f"Falha ao ligar a {self.base_url}/login.php: {last_err}"
            ) from last_err

        if "setup.php" in final_url or "First time using DVWA" in body:
            self._initialize_db()
            status, final_url, body, _ = self._request("/login.php", "GET")

        if status >= 400:
            raise RuntimeError(
                f"Falha ao aceder a {self.base_url}/login.php (HTTP {status})."
            )

        token = self._extract_user_token(body)
        login_payload = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            login_payload["user_token"] = token

        _, login_url, login_body, _ = self._request("/login.php", "POST", login_payload)
        if not self._login_succeeded(login_url, login_body):
            # Quando a BD ainda nao tem tabelas, o POST /login.php redireciona para /setup.php
            self._initialize_db()

            _, _, body, _ = self._request("/login.php", "GET")
            token = self._extract_user_token(body)
            if token:
                login_payload["user_token"] = token
            _, login_url, login_body, _ = self._request(
                "/login.php", "POST", login_payload
            )
            if not self._login_succeeded(login_url, login_body):
                raise RuntimeError("Nao foi possivel autenticar na DVWA.")

        # Define nivel de seguranca low na sessao e no cookie
        _, _, sec_body, _ = self._request("/security.php", "GET")
        sec_token = self._extract_user_token(sec_body)
        sec_payload = {"security": "low", "seclev_submit": "Submit"}
        if sec_token:
            sec_payload["user_token"] = sec_token
        self._request("/security.php", "POST", sec_payload)
        self._set_cookie("security", "low")

        # Verifica explicitamente que a sessao autenticada acede a /vulnerabilities/sqli/ sem redirect para login.php
        v_status, v_url, v_body, _ = self._request(
            "/vulnerabilities/sqli/?id=1&Submit=Submit", "GET"
        )
        if v_status != 200 or "login.php" in v_url or "First name" not in v_body:
            raise RuntimeError(
                f"Sessao DVWA nao ficou autenticada em {self.base_url} "
                f"(HTTP {v_status}, URL final: {v_url})."
            )

        return self.get_phpsessid()

    def send_test_case(self, row: dict[str, str]) -> tuple[int, float, str, str]:
        """Envia um caso de teste (ataque ou pedido legitimo) para a DVWA."""
        endpoint = row["endpoint"]
        method = row["method"].upper()
        param = row["param"]
        payload = row["payload"].replace("\\t", "\t")

        if method == "GET":
            params = {param: payload}
            if "sqli" in endpoint:
                params["Submit"] = "Submit"
            query = urllib.parse.urlencode(params)
            status, final_url, body, elapsed_ms = self._request(
                f"{endpoint}?{query}", "GET"
            )
            return status, elapsed_ms, body, final_url

        if method == "POST":
            form_data = {
                "txtName": "SRSI Tester",
                "mtxMessage": "Mensagem de teste SRSI",
                "btnSign": "Sign Guestbook",
            }
            form_data[param] = payload
            status, final_url, body, elapsed_ms = self._request(
                endpoint, "POST", form_data
            )
            return status, elapsed_ms, body, final_url

        raise ValueError(f"Metodo HTTP nao suportado: {method}")


def load_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t", quoting=csv.QUOTE_NONE))


def safe_div(num: float, den: float) -> float:
    return num / den if den > 0 else 0.0


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | int]:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    specificity = safe_div(tn, tn + fp)
    balanced_accuracy = 0.5 * (recall + specificity)
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "specificity": round(specificity, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
    }


def summarize_audit_log(audit_path: Path) -> dict[str, object]:
    """Extrai estatisticas do ficheiro JSON audit.log do ModSecurity (Fase 5)."""
    if not audit_path.exists():
        return {"exists": False, "transactions": 0, "top_rules": []}

    transactions = 0
    blocked_tx = 0
    rule_counter: Counter[tuple[str, str]] = Counter()
    phase_counter: Counter[str] = Counter()

    with audit_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            tx = entry.get("transaction", {})
            transactions += 1
            http_code = tx.get("response", {}).get("http_code")
            if http_code == 403:
                blocked_tx += 1

            for msg in tx.get("messages", []):
                details = msg.get("details", {})
                rule_id = str(details.get("ruleId", "unknown"))
                rule_msg = str(msg.get("message", "")).strip()
                phase = str(details.get("phase", ""))
                if phase:
                    phase_counter[phase] += 1
                rule_counter[(rule_id, rule_msg)] += 1

    top_rules = [
        {"rule_id": rid, "message": rmsg, "hits": count}
        for (rid, rmsg), count in rule_counter.most_common(15)
    ]
    return {
        "exists": True,
        "transactions": transactions,
        "blocked_http_403": blocked_tx,
        "phases": dict(phase_counter),
        "top_rules": top_rules,
    }


def evaluate_suite(
    waf_url: str,
    baseline_url: str | None,
    attacks_path: Path,
    legit_path: Path,
    audit_log_path: Path,
    results_dir: Path,
) -> None:
    attacks = load_tsv(attacks_path)
    legitimate = load_tsv(legit_path)

    if baseline_url:
        print(f"[*] A inicializar sessao DVWA no Baseline ({baseline_url})...")
        base_client = DvwaSession(baseline_url)
        base_sess = base_client.ensure_ready()
        print(f"[+] Sessao Baseline pronta (PHPSESSID={base_sess})")
    else:
        base_client = None

    print(f"[*] A inicializar sessao DVWA no WAF ({waf_url})...")
    waf_client = DvwaSession(waf_url)
    waf_sess = waf_client.ensure_ready()
    print(f"[+] Sessao WAF pronta (PHPSESSID={waf_sess})")
    print(
        f"    Dica para sqlmap/ab/cURL: --cookie=\"PHPSESSID={waf_sess}; security=low\""
    )

    detailed_rows: list[dict[str, object]] = []
    category_counts: dict[str, Counter[str]] = defaultdict(Counter)
    tp = fp = tn = fn = 0

    print("\n[*] A executar conjunto de ATAQUES contra o WAF...")
    for row in attacks:
        base_status = ""
        if base_client is not None:
            b_code, _, _, b_url = base_client.send_test_case(row)
            base_status = "302->login" if "login.php" in b_url else b_code

        w_code, w_ms, _, w_final_url = waf_client.send_test_case(row)
        blocked = w_code == 403
        label = "TP" if blocked else "FN"
        if blocked:
            tp += 1
        else:
            fn += 1
        category_counts[row["category"]][label] += 1

        print(
            f"  [{label}] {row['id']} ({row['category']}) -> "
            f"WAF HTTP {w_code} ({w_ms:.1f} ms)"
            + (f" | Base HTTP {base_status}" if base_status != "" else "")
            + (" [WARN: WAF redirect login]" if "login.php" in w_final_url else "")
        )
        detailed_rows.append(
            {
                "id": row["id"],
                "split": "attack",
                "category": row["category"],
                "endpoint": row["endpoint"],
                "method": row["method"],
                "param": row["param"],
                "payload": row["payload"],
                "baseline_http": base_status,
                "waf_http": w_code,
                "waf_latency_ms": round(w_ms, 2),
                "classification": label,
            }
        )

    print("\n[*] A executar conjunto de TRAFEGO LEGITIMO contra o WAF...")
    for row in legitimate:
        base_status = ""
        if base_client is not None:
            b_code, _, _, b_url = base_client.send_test_case(row)
            base_status = "302->login" if "login.php" in b_url else b_code

        w_code, w_ms, _, w_final_url = waf_client.send_test_case(row)
        blocked = w_code == 403
        label = "FP" if blocked else "TN"
        if blocked:
            fp += 1
        else:
            tn += 1
        category_counts[row["category"]][label] += 1

        print(
            f"  [{label}] {row['id']} ({row['category']}) -> "
            f"WAF HTTP {w_code} ({w_ms:.1f} ms)"
            + (f" | Base HTTP {base_status}" if base_status != "" else "")
            + (" [WARN: WAF redirect login]" if "login.php" in w_final_url else "")
        )
        detailed_rows.append(
            {
                "id": row["id"],
                "split": "legitimate",
                "category": row["category"],
                "endpoint": row["endpoint"],
                "method": row["method"],
                "param": row["param"],
                "payload": row["payload"],
                "baseline_http": base_status,
                "waf_http": w_code,
                "waf_latency_ms": round(w_ms, 2),
                "classification": label,
            }
        )

    metrics = compute_metrics(tp, fp, tn, fn)
    audit_summary = summarize_audit_log(audit_log_path)

    results_dir.mkdir(parents=True, exist_ok=True)
    csv_out = results_dir / "detailed_results.csv"
    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = list(detailed_rows[0].keys())
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(detailed_rows)

    summary_payload = {
        "waf_url": waf_url,
        "baseline_url": baseline_url,
        "metrics": metrics,
        "by_category": {cat: dict(cnt) for cat, cnt in category_counts.items()},
        "audit_log_summary": audit_summary,
    }
    json_out = results_dir / "metrics_summary.json"
    with json_out.open("w", encoding="utf-8") as handle:
        json.dump(summary_payload, handle, indent=2, ensure_ascii=False)

    print("\n=== MATRIZ DE CONFUSAO & METRICAS (Seccao 4.1) ===")
    print(f"TP={tp} | FP={fp} | TN={tn} | FN={fn}")
    print(f"Precisao (Precision):          {metrics['precision']:.4f}")
    print(f"Sensibilidade (Recall):        {metrics['recall']:.4f}")
    print(f"F1-Score:                      {metrics['f1_score']:.4f}")
    print(f"Especificidade:                {metrics['specificity']:.4f}")
    print(f"Acuracia Balanceada (BA):      {metrics['balanced_accuracy']:.4f}")

    if audit_summary["exists"]:
        print("\n=== RESUMO DO MODSECURITY AUDIT.LOG ===")
        print(
            f"Transacoes registadas: {audit_summary['transactions']} "
            f"(HTTP 403: {audit_summary['blocked_http_403']})"
        )
        for item in audit_summary["top_rules"][:10]:
            print(
                f"  Rule {item['rule_id']} ({item['hits']}x): {item['message']}"
            )
    else:
        print(f"\n[!] Ficheiro audit.log nao encontrado em {audit_log_path}")

    print(f"\n[+] Resultados guardados em:\n  - {csv_out}\n  - {json_out}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Avalia detecao (TP/FP/TN/FN) do WAF ModSecurity na DVWA."
    )
    parser.add_argument(
        "--waf-url",
        default="http://127.0.0.1:8080",
        help="URL do Nginx+ModSecurity WAF (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--baseline-url",
        default="http://127.0.0.1:8082",
        help="URL do Proxy Nginx sem WAF (default: http://127.0.0.1:8082; vazio para omitir)",
    )
    parser.add_argument("--attacks", type=Path, default=DEFAULT_ATTACKS)
    parser.add_argument("--legitimate", type=Path, default=DEFAULT_LEGIT)
    parser.add_argument("--audit-log", type=Path, default=DEFAULT_AUDIT_LOG)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument(
        "--print-cookie",
        action="store_true",
        help="Inicializa a DVWA no --waf-url e imprime apenas PHPSESSID=<valor>; security=low",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.print_cookie:
        sess = DvwaSession(args.waf_url).ensure_ready()
        print(f"PHPSESSID={sess}; security=low")
    else:
        baseline = args.baseline_url.strip() or None
        evaluate_suite(
            waf_url=args.waf_url,
            baseline_url=baseline,
            attacks_path=args.attacks,
            legit_path=args.legitimate,
            audit_log_path=args.audit_log,
            results_dir=args.results_dir,
        )
