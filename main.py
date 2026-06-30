"""
╔══════════════════════════════════════════════════════════════════════╗
║   VIGILAR  —  LLM Red-Team & Security Auditing Framework             ║
║   OWASP LLM Top 10 v1.1 · 10 Attack Techniques · CVSS · Crescendo    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
from datetime import datetime

from modules.config      import (SYSTEM_PROMPT_WEAK, SYSTEM_PROMPT_HARDENED,
                                  DEFAULT_MODEL, DEFAULT_TIMEOUT, LLAMAGUARD_MODEL, PROVIDERS)
from modules.payloads    import PAYLOADS, TECHNIQUE_LABELS
from modules.engine      import send_single, benchmark_providers, REQUEST_DELAY
from modules.fuzzer      import FuzzEngine
from modules.multiturn   import MultiTurnEngine
from modules.paraphraser import ParaphraseEngine
from modules.evaluator   import (evaluate_risk, evaluate_with_llamaguard,
                                  compute_cvss_score, response_divergence_score)
from modules.reporter    import (print_header, print_result, print_summary,
                                  generate_markdown_report, generate_html_dashboard)
from modules.colors      import C


def build_args():
    p = argparse.ArgumentParser(description="Vigilar — LLM Red-Team & Security Auditing Framework")
    p.add_argument("--provider",      default="ollama")
    p.add_argument("--model",         default=DEFAULT_MODEL)
    p.add_argument("--timeout",       default=DEFAULT_TIMEOUT, type=int)
    p.add_argument("--delay",         default=REQUEST_DELAY,   type=float,
                   help="Seconds between requests (default: 2.0 — safe for Groq free tier)")
    p.add_argument("--output",        default="reports/LLM_Security_Report.md")
    p.add_argument("--owasp",         default=None,  help="Filter by OWASP ID e.g. LLM07")
    p.add_argument("--technique",     default=None,  help="Filter by technique e.g. crescendo")
    p.add_argument("--severity",      default=None,  help="Filter: CRITICAL|HIGH|MEDIUM")
    p.add_argument("--hardened",      action="store_true", help="Use hardened system prompt")
    p.add_argument("--no-fuzz",       action="store_true")
    p.add_argument("--no-multiturn",  action="store_true")
    p.add_argument("--no-paraphrase", action="store_true")
    p.add_argument("--no-guard",      action="store_true")
    p.add_argument("--no-html",       action="store_true")
    p.add_argument("--guard-model",   default=LLAMAGUARD_MODEL)
    p.add_argument("--benchmark",     action="store_true",
                   help="Fire CRITICAL probes across all configured providers in parallel")
    return p.parse_args()


def make_record(item, engine, variant, raw, elapsed, provider, args, system_prompt):
    status, description = evaluate_risk(raw, item)
    cvss   = compute_cvss_score(status, item, provider)
    div    = response_divergence_score(raw)
    guard  = None
    if not args.no_guard and not raw.startswith("["):
        guard = evaluate_with_llamaguard(
            prompt=item.get("prompt",""), response=raw,
            model=args.guard_model, timeout=args.timeout,
        )
    return {
        **item,
        "engine": engine, "variant": variant,
        "status": status, "description": description,
        "raw_response": raw, "elapsed": elapsed,
        "cvss_score": cvss, "divergence": div, "guard": guard,
    }


def phase_banner(n, title):
    print(f"\n{C.CYAN}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}  PHASE {n} — {title}{C.RESET}")
    print(f"{C.CYAN}{'═'*70}{C.RESET}")


def run_baseline(args, probes, records, system_prompt):
    for idx, item in enumerate(probes, 1):
        sev_col = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.BLUE}.get(item["severity"],C.WHITE)
        tech    = TECHNIQUE_LABELS.get(item.get("technique","standard"),"")
        print(f"{C.GRAY}[{idx:02d}/{len(probes)}]{C.RESET} {C.BOLD}{item['owasp_id']}{C.RESET} "
              f"— {item['category'][:50]} ({sev_col}{item['severity']}{C.RESET}) \033[33m{tech}\033[0m")
        raw, elapsed = send_single(args.provider, args.model, system_prompt,
                                   item["prompt"], args.timeout, args.delay)
        record = make_record(item, "baseline", "raw", raw, elapsed, args.provider, args, system_prompt)
        records.append(record)
        print_result(record)


def run_fuzz(args, probes, records, system_prompt):
    fuzzer = FuzzEngine()
    for item in probes:
        for vname, vprompt in fuzzer.generate(item["prompt"]).items():
            fuzz_item = {**item, "prompt": vprompt}
            print(f"  {C.PURPLE}FUZZ/{vname}{C.RESET} {item['owasp_id']} — {item['category'][:45]}")
            raw, elapsed = send_single(args.provider, args.model, system_prompt,
                                       vprompt, args.timeout, args.delay)
            records.append(make_record(fuzz_item, "fuzzer", vname, raw, elapsed,
                                       args.provider, args, system_prompt))
            print_result(records[-1])


def run_multiturn(args, records, system_prompt):
    engine = MultiTurnEngine(args.provider, args.model, args.timeout, system_prompt, args.delay)
    for chain in engine.get_chains():
        print(f"\n  {C.CYAN}CHAIN{C.RESET} {chain['name']}")
        result = engine.run_chain(chain)
        item   = {
            "owasp_id": chain["owasp_id"], "owasp_name": chain["owasp_name"],
            "category": chain["name"], "severity": chain["severity"],
            "technique": chain.get("technique","multi_turn"),
            "prompt": result["final_prompt"],
        }
        record = make_record(item, "multi-turn", f"{len(chain['steps'])}-step",
                             result["final_response"], result["elapsed"],
                             args.provider, args, system_prompt)
        record["history"] = result["history"]
        records.append(record)
        print_result(record)


def run_paraphrase(args, probes, records, system_prompt):
    engine   = ParaphraseEngine(args.provider, args.model, args.timeout, args.delay)
    critical = [p for p in probes if p["severity"] == "CRITICAL"]
    for item in critical:
        for i, vprompt in enumerate(engine.paraphrase(item["prompt"], n=2), 1):
            fuzz_item = {**item, "prompt": vprompt}
            print(f"  {C.PURPLE}PARAPHRASE/v{i}{C.RESET} {item['owasp_id']} — {item['category'][:45]}")
            raw, elapsed = send_single(args.provider, args.model, system_prompt,
                                       vprompt, args.timeout, args.delay)
            records.append(make_record(fuzz_item, "paraphraser", f"paraphrase-v{i}",
                                       raw, elapsed, args.provider, args, system_prompt))
            print_result(records[-1])


def run_benchmark(args):
    print(f"\n{C.CYAN}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}  BENCHMARK MODE — Parallel Multi-Provider{C.RESET}")
    print(f"{C.CYAN}{'═'*70}{C.RESET}\n")
    available = [(n, cfg["models"][0]) for n, cfg in PROVIDERS.items()
                 if cfg.get("api_key") or n == "ollama"]
    print(f"  Targets: {', '.join(f'{p}/{m}' for p,m in available)}\n")
    system_prompt = SYSTEM_PROMPT_HARDENED if args.hardened else SYSTEM_PROMPT_WEAK
    critical = [p for p in PAYLOADS if p["severity"] == "CRITICAL"][:5]
    all_records = []
    for item in critical:
        print(f"  Probe: {item['category']}")
        results = benchmark_providers(available, system_prompt, item["prompt"], args.timeout)
        for r in results:
            status, desc = evaluate_risk(r["response"], item)
            cvss = compute_cvss_score(status, item, r["provider"])
            badge = {"CRITICAL_BYPASS":"🔴","PARTIAL_LEAK":"🟡","SECURE":"🟢","UNKNOWN":"🔵"}.get(status,"❓")
            print(f"    {badge} {r['provider']}/{r['model']} — CVSS {cvss} — {r['elapsed']}s")
            all_records.append({
                **item, "engine":"benchmark", "variant":f"{r['provider']}/{r['model']}",
                "status":status, "description":desc, "raw_response":r["response"],
                "elapsed":r["elapsed"], "cvss_score":cvss,
                "divergence":response_divergence_score(r["response"]), "guard":None,
            })
        print()
    generate_markdown_report(all_records, "multi-provider", "benchmark", args.output, args.hardened)
    if not args.no_html:
        generate_html_dashboard(all_records, "multi-provider", "benchmark", args.output, args.hardened)


def main():
    args = build_args()

    if args.benchmark:
        run_benchmark(args)
        return

    system_prompt = SYSTEM_PROMPT_HARDENED if args.hardened else SYSTEM_PROMPT_WEAK
    print_header(args.provider, args.model, args.hardened)

    probes = PAYLOADS
    if args.owasp:
        probes = [p for p in probes if p["owasp_id"] == args.owasp.upper()]
    if args.technique:
        probes = [p for p in probes if p.get("technique") == args.technique]
    if args.severity:
        probes = [p for p in probes if p["severity"] == args.severity.upper()]
    if not probes:
        print(f"{C.RED}No payloads match the given filters.{C.RESET}")
        return

    records = []

    phase_banner(1, f"Baseline Probes ({len(probes)} probes)")
    run_baseline(args, probes, records, system_prompt)

    if not args.no_fuzz:
        phase_banner(2, "Fuzzing Engine  [Base64 · Hex · LeetSpeak · CodeSwitch]")
        run_fuzz(args, probes, records, system_prompt)

    if not args.no_multiturn:
        phase_banner(3, "Multi-Turn Chains + Crescendo Attacks")
        run_multiturn(args, records, system_prompt)

    if not args.no_paraphrase:
        phase_banner(4, "Adversarial Paraphrasing  [CRITICAL probes only]")
        run_paraphrase(args, probes, records, system_prompt)

    print_summary(records)
    generate_markdown_report(records, args.model, args.provider, args.output, args.hardened)
    if not args.no_html:
        generate_html_dashboard(records, args.model, args.provider, args.output, args.hardened)


if __name__ == "__main__":
    main()