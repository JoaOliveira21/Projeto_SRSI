#!/usr/bin/env python3
"""
Benchmark de desempenho e latencia (Seccao 4.2 do relatorio) com Apache Benchmark (ab).

Mede L_Base (Nginx sem WAF) e L_WAF (Nginx + ModSecurity v3 + OWASP CRS)
e calcula Delta L = L_WAF - L_Base para diferentes niveis de concorrencia.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
from pathlib import Path

from run_evaluation import DvwaSession


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
DEFAULT_RESULTS_DIR = SRC_DIR / "results"


def run_ab_command(
    target_url: str,
    requests_count: int,
    concurrency: int,
    cookie_header: str,
    docker_network: str,
) -> str:
    """Executa Apache Benchmark (ab) localmente ou via contentor httpd:alpine."""
    local_ab = shutil.which("ab")
    if local_ab:
        cmd = [
            local_ab,
            "-n",
            str(requests_count),
            "-c",
            str(concurrency),
            "-C",
            cookie_header,
            target_url,
        ]
    else:
        ab_shell = (
            "apk add --no-cache apache2-utils >/dev/null && "
            f"ab -n {requests_count} -c {concurrency} -C '{cookie_header}' '{target_url}'"
        )
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            docker_network,
            "httpd:alpine",
            "sh",
            "-c",
            ab_shell,
        ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Falha ao executar Apache Benchmark para {target_url}:\n{proc.stderr}"
        )
    return proc.stdout


def parse_ab_output(output: str) -> dict[str, float | int]:
    """Extrai latencia media, RPS, falhas e percentis do output do ab."""
    def extract_float(pattern: str) -> float:
        match = re.search(pattern, output)
        return float(match.group(1)) if match else 0.0

    def extract_int(pattern: str) -> int:
        match = re.search(pattern, output)
        return int(match.group(1)) if match else 0

    return {
        "complete_requests": extract_int(r"Complete requests:\s+(\d+)"),
        "failed_requests": extract_int(r"Failed requests:\s+(\d+)"),
        "requests_per_sec": extract_float(r"Requests per second:\s+([\d.]+)"),
        "mean_latency_ms": extract_float(
            r"Time per request:\s+([\d.]+)\s+\[ms\]\s+\(mean\)"
        ),
        "p50_ms": extract_float(r"50%\s+([\d.]+)"),
        "p95_ms": extract_float(r"95%\s+([\d.]+)"),
        "p99_ms": extract_float(r"99%\s+([\d.]+)"),
    }


def run_benchmarks(
    base_url: str,
    waf_url: str,
    ab_base_url: str | None,
    ab_waf_url: str | None,
    endpoint: str,
    requests_count: int,
    concurrencies: list[int],
    docker_network: str,
    results_dir: Path,
) -> None:
    local_ab = shutil.which("ab") is not None
    eff_ab_base = ab_base_url or (base_url if local_ab else "http://proxy-base:80")
    eff_ab_waf = ab_waf_url or (waf_url if local_ab else "http://waf:8080")

    print("[*] A obter sessao valida da DVWA para o Apache Benchmark...")
    base_session = DvwaSession(base_url).ensure_ready()
    waf_session = DvwaSession(waf_url).ensure_ready()

    base_cookie = f"PHPSESSID={base_session}; security=low"
    waf_cookie = f"PHPSESSID={waf_session}; security=low"

    rows: list[dict[str, object]] = []
    for conc in concurrencies:
        print(f"\n[*] Benchmark c={conc}, n={requests_count} em {endpoint} ...")
        base_out = run_ab_command(
            f"{eff_ab_base.rstrip('/')}{endpoint}",
            requests_count,
            conc,
            base_cookie,
            docker_network,
        )
        base_stats = parse_ab_output(base_out)

        waf_out = run_ab_command(
            f"{eff_ab_waf.rstrip('/')}{endpoint}",
            requests_count,
            conc,
            waf_cookie,
            docker_network,
        )
        waf_stats = parse_ab_output(waf_out)

        delta_l = round(
            float(waf_stats["mean_latency_ms"]) - float(base_stats["mean_latency_ms"]),
            3,
        )
        overhead_pct = (
            round((delta_l / float(base_stats["mean_latency_ms"])) * 100.0, 2)
            if float(base_stats["mean_latency_ms"]) > 0
            else 0.0
        )

        row = {
            "concurrency": conc,
            "requests": requests_count,
            "endpoint": endpoint,
            "L_Base_ms": base_stats["mean_latency_ms"],
            "L_WAF_ms": waf_stats["mean_latency_ms"],
            "Delta_L_ms": delta_l,
            "overhead_pct": overhead_pct,
            "Base_RPS": base_stats["requests_per_sec"],
            "WAF_RPS": waf_stats["requests_per_sec"],
            "Base_p95_ms": base_stats["p95_ms"],
            "WAF_p95_ms": waf_stats["p95_ms"],
            "Base_failed": base_stats["failed_requests"],
            "WAF_failed": waf_stats["failed_requests"],
        }
        rows.append(row)
        print(
            f"  L_Base = {row['L_Base_ms']} ms ({row['Base_RPS']} req/s) | "
            f"L_WAF = {row['L_WAF_ms']} ms ({row['WAF_RPS']} req/s) | "
            f"Delta L = {delta_l:+.3f} ms ({overhead_pct:+.2f}%)"
        )

    results_dir.mkdir(parents=True, exist_ok=True)
    csv_out = results_dir / "latency_benchmark.csv"
    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    json_out = results_dir / "latency_benchmark.json"
    with json_out.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, ensure_ascii=False)

    print(f"\n[+] Benchmark guardado em:\n  - {csv_out}\n  - {json_out}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mede impacto de latencia Delta L com Apache Benchmark (ab)."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8082")
    parser.add_argument("--waf-url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--ab-base-url",
        default=None,
        help="URL opcional para o ab atingir o proxy baseline (auto: localhost se ab local, http://proxy-base:80 se Docker)",
    )
    parser.add_argument(
        "--ab-waf-url",
        default=None,
        help="URL opcional para o ab atingir o WAF (auto: localhost se ab local, http://waf:8080 se Docker)",
    )
    parser.add_argument(
        "--endpoint",
        default="/vulnerabilities/sqli/?id=1&Submit=Submit",
    )
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument(
        "--concurrency",
        default="10,50",
        help="Niveis de concorrencia separados por virgula (ex: 10,50)",
    )
    parser.add_argument("--docker-network", default="srsi_net")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    concs = [int(item.strip()) for item in args.concurrency.split(",") if item.strip()]
    run_benchmarks(
        base_url=args.base_url,
        waf_url=args.waf_url,
        ab_base_url=args.ab_base_url,
        ab_waf_url=args.ab_waf_url,
        endpoint=args.endpoint,
        requests_count=args.requests,
        concurrencies=concs,
        docker_network=args.docker_network,
        results_dir=args.results_dir,
    )
