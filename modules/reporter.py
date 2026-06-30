# ─────────────────────────────────────────────────────────────────
#  modules/reporter.py  —  Terminal + Markdown + Elite HTML Dashboard
# ─────────────────────────────────────────────────────────────────

import os
import json
from datetime import datetime
from modules.colors import C, SEVERITY_COLOR, STATUS_ICON, GUARD_ICON
from modules.payloads import TECHNIQUE_LABELS


# ── Terminal ──────────────────────────────────────────────────────

def print_header(provider, model, hardened=False):
    mode = f"{C.YELLOW}⚠ HARDENED{C.RESET}" if hardened else f"{C.RED}◉ WEAK{C.RESET}"
    print(f"\n{C.CYAN}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  🛡️  VIGILAR{C.RESET}")
    print(f"{C.GRAY}  LLM Red-Team & Security Auditing Framework{C.RESET}")
    print(f"{C.GRAY}  OWASP LLM Top 10 v1.1 · 10 Attack Techniques · CVSS Scoring{C.RESET}")
    print(f"{C.GRAY}  Provider : {C.WHITE}{provider}{C.RESET}  {C.GRAY}Model : {C.WHITE}{model}{C.RESET}  System Prompt: {mode}")
    print(f"{C.GRAY}  Started  : {C.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.CYAN}{'═'*70}{C.RESET}\n")

def print_result(record):
    sev_col   = SEVERITY_COLOR.get(record.get("severity",""), C.WHITE)
    status    = STATUS_ICON.get(record["status"], record["status"])
    technique = TECHNIQUE_LABELS.get(record.get("technique","standard"), "")
    cvss      = record.get("cvss_score", 0.0)
    guard     = record.get("guard")
    cvss_col  = C.RED if cvss >= 7 else C.YELLOW if cvss >= 4 else C.GREEN
    print(f"  {C.BOLD}{record.get('owasp_id','')}{C.RESET} "
          f"[{C.PURPLE}{record.get('engine','')}{C.RESET}/{C.GRAY}{record.get('variant','raw')}{C.RESET}] "
          f"\033[33m{technique}\033[0m")
    print(f"  Severity  : {sev_col}{record.get('severity','?')}{C.RESET}  CVSS: {cvss_col}{cvss}{C.RESET}")
    print(f"  Result    : {status}")
    if guard:
        print(f"  Guard     : {GUARD_ICON.get(guard, guard)}")
    print(f"  Detail    : {C.GRAY}{record['description']}{C.RESET}")
    print(f"  Time      : {C.GRAY}{record.get('elapsed','?')}s{C.RESET}")
    print()

def print_summary(records):
    counts      = {"SECURE":0,"PARTIAL_LEAK":0,"CRITICAL_BYPASS":0,"UNKNOWN":0}
    guard_counts= {"SAFE":0,"UNSAFE":0,"ERROR":0}
    cvss_scores = []
    for r in records:
        counts[r["status"]] = counts.get(r["status"],0) + 1
        g = r.get("guard")
        if g:
            guard_counts[g] = guard_counts.get(g,0) + 1
        if r.get("cvss_score",0) > 0:
            cvss_scores.append(r["cvss_score"])
    total      = len(records)
    risk_score = round((counts["CRITICAL_BYPASS"]*10+counts["PARTIAL_LEAK"]*5+counts["UNKNOWN"]*2)/max(total,1),1)
    avg_cvss   = round(sum(cvss_scores)/len(cvss_scores),1) if cvss_scores else 0.0
    max_cvss   = max(cvss_scores) if cvss_scores else 0.0
    bar_len    = min(int(risk_score*5),55)
    bar_col    = C.RED if risk_score>=6 else C.YELLOW if risk_score>=3 else C.GREEN
    print(f"\n{C.CYAN}{'─'*70}{C.RESET}")
    print(f"{C.BOLD}  📊  SUMMARY  ({total} total probes){C.RESET}")
    print(f"{C.CYAN}{'─'*70}{C.RESET}")
    print(f"  {STATUS_ICON['SECURE']}          : {counts['SECURE']}")
    print(f"  {STATUS_ICON['PARTIAL_LEAK']}    : {counts['PARTIAL_LEAK']}")
    print(f"  {STATUS_ICON['CRITICAL_BYPASS']} : {counts['CRITICAL_BYPASS']}")
    print(f"  {STATUS_ICON['UNKNOWN']}         : {counts['UNKNOWN']}")
    if any(guard_counts.values()):
        print(f"\n  {C.BOLD}Llama Guard{C.RESET}  🛡️ {guard_counts['SAFE']}  ⚠️ {guard_counts['UNSAFE']}")
    print(f"\n  CVSS  avg={C.YELLOW}{avg_cvss}{C.RESET}  max={C.RED}{max_cvss}{C.RESET}")
    print(f"\n  Risk Score : {bar_col}{'█'*bar_len}{'░'*(55-bar_len)} {risk_score}/10{C.RESET}\n")


# ── Markdown ──────────────────────────────────────────────────────

def generate_markdown_report(records, model, provider, output_path, hardened=False):
    counts = {"SECURE":0,"PARTIAL_LEAK":0,"CRITICAL_BYPASS":0,"UNKNOWN":0}
    for r in records:
        counts[r["status"]] = counts.get(r["status"],0) + 1
    total      = len(records)
    risk_score = round((counts["CRITICAL_BYPASS"]*10+counts["PARTIAL_LEAK"]*5+counts["UNKNOWN"]*2)/max(total,1),1)
    cvss_scores= [r.get("cvss_score",0) for r in records if r.get("cvss_score",0)>0]
    avg_cvss   = round(sum(cvss_scores)/len(cvss_scores),1) if cvss_scores else 0.0
    STATUS_BADGE={"SECURE":"🟢 SECURE","PARTIAL_LEAK":"🟡 PARTIAL LEAK","CRITICAL_BYPASS":"🔴 CRITICAL BYPASS","UNKNOWN":"🔵 UNKNOWN"}
    lines = [
        "# 🛡️ Vigilar — LLM Security Audit Report","",
        "|Field|Value|","|---|---|",
        f"|**Provider**|`{provider}`|",f"|**Model**|`{model}`|",
        f"|**System Prompt**|{'Hardened' if hardened else 'Weak (Default)'}|",
        f"|**Standard**|OWASP Top 10 for LLM Applications v1.1|",
        f"|**Techniques**|Standard · Fuzzing · Multi-Turn · Crescendo · Many-Shot · Competing Objectives · Reflection|",
        f"|**Date**|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|",
        f"|**Total Probes**|{total}|",f"|**Risk Score**|**{risk_score} / 10**|",f"|**Avg CVSS**|**{avg_cvss} / 10**|",
        "","---","","## 📊 Executive Summary","",
        "|Status|Count|","|---|---|",
        f"|🟢 Secure|{counts['SECURE']}|",f"|🟡 Partial Leak|{counts['PARTIAL_LEAK']}|",
        f"|🔴 Critical Bypass|{counts['CRITICAL_BYPASS']}|",f"|🔵 Unknown|{counts['UNKNOWN']}|",
        "","---","","## 🔍 Detailed Findings","",
    ]
    engine_order  = ["baseline","fuzzer","multi-turn","paraphraser"]
    engine_titles = {"baseline":"Phase 1 — Baseline Probes","fuzzer":"Phase 2 — Fuzzing Engine",
                     "multi-turn":"Phase 3 — Multi-Turn & Crescendo Chains","paraphraser":"Phase 4 — Adversarial Paraphrasing"}
    grouped = {}
    for r in records:
        grouped.setdefault(r.get("engine","baseline"),[]).append(r)
    n = 1
    for engine in engine_order:
        recs = grouped.get(engine,[])
        if not recs: continue
        lines += [f"### {engine_titles.get(engine,engine)}",""]
        for r in recs:
            technique = TECHNIQUE_LABELS.get(r.get("technique","standard"),"")
            lines += [
                f"#### Probe {n} — {r.get('category','')} `[{r.get('variant','raw')}]`","",
                "|Field|Value|","|---|---|",
                f"|**OWASP**|{r.get('owasp_id','')} — {r.get('owasp_name','')}|",
                f"|**Technique**|{technique}|",f"|**Severity**|{r.get('severity','?')}|",
                f"|**CVSS Score**|{r.get('cvss_score',0.0)} / 10|",
                f"|**Heuristic**|{STATUS_BADGE.get(r['status'],r['status'])}|",
                f"|**Llama Guard**|{r.get('guard','—')}|",f"|**Divergence**|{r.get('divergence','—')}|",
                f"|**Time**|{r.get('elapsed','?')}s|",f"|**Analysis**|{r['description']}|",
                "","**Adversarial Probe:**","```",r.get("prompt","")[:500],"```","",
                "**Model Response:**","```",
                r.get("raw_response","")[:600]+("…[truncated]" if len(r.get("raw_response",""))>600 else ""),
                "```","",
            ]
            if r.get("history"):
                lines.append("<details><summary>Full conversation history</summary>\n")
                for msg in r["history"]:
                    lines.append(f"**{msg['role'].upper()}:** {msg['content'][:300]}\n")
                lines += ["</details>",""]
            n += 1
    lines += ["---","","## ⚠️ Disclaimer","",
              "Security research and educational purposes only. All tests conducted in a controlled environment.",""]
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path,"w",encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {C.GREEN}✔{C.RESET}  Markdown → {C.WHITE}{os.path.abspath(output_path)}{C.RESET}")


# ── Elite HTML Dashboard ──────────────────────────────────────────

def generate_html_dashboard(records, model, provider, output_path, hardened=False):
    counts       = {"SECURE":0,"PARTIAL_LEAK":0,"CRITICAL_BYPASS":0,"UNKNOWN":0}
    owasp_counts = {}
    tech_counts  = {}
    cvss_scores  = []
    for r in records:
        counts[r["status"]] = counts.get(r["status"],0) + 1
        oid = r.get("owasp_id","?")
        owasp_counts.setdefault(oid,{"SECURE":0,"PARTIAL_LEAK":0,"CRITICAL_BYPASS":0,"UNKNOWN":0})
        owasp_counts[oid][r["status"]] += 1
        t = r.get("technique","standard")
        tech_counts[t] = tech_counts.get(t,0) + 1
        if r.get("cvss_score",0) > 0:
            cvss_scores.append(r["cvss_score"])
    total      = len(records)
    risk_score = round((counts["CRITICAL_BYPASS"]*10+counts["PARTIAL_LEAK"]*5+counts["UNKNOWN"]*2)/max(total,1),1)
    avg_cvss   = round(sum(cvss_scores)/len(cvss_scores),1) if cvss_scores else 0.0
    max_cvss   = max(cvss_scores) if cvss_scores else 0.0

    records_json = json.dumps([{
        "owasp_id"  : r.get("owasp_id",""),
        "owasp_name": r.get("owasp_name",""),
        "category"  : r.get("category",""),
        "severity"  : r.get("severity",""),
        "technique" : TECHNIQUE_LABELS.get(r.get("technique","standard"),"Standard"),
        "engine"    : r.get("engine","baseline"),
        "variant"   : r.get("variant","raw"),
        "status"    : r["status"],
        "cvss_score": r.get("cvss_score",0.0),
        "guard"     : r.get("guard","—"),
        "divergence": r.get("divergence","—"),
        "description": r["description"],
        "prompt"    : r.get("prompt","")[:400],
        "response"  : r.get("raw_response","")[:500],
        "elapsed"   : r.get("elapsed",0),
    } for r in records], indent=2)

    risk_color = "#f43f5e" if risk_score>=7 else "#f59e0b" if risk_score>=4 else "#22c55e"
    hardened_badge = ('<span class="badge badge-hardened">⚡ HARDENED</span>' if hardened
                      else '<span class="badge badge-weak">⚠ WEAK</span>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Vigilar — LLM Security Auditor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {{
    --bg:        #0a0a0f;
    --surface:   #12121a;
    --surface2:  #1a1a28;
    --border:    #2a2a3f;
    --border2:   #3a3a55;
    --text:      #e2e2f0;
    --muted:     #7070a0;
    --accent:    #8b5cf6;
    --accent2:   #a78bfa;
    --red:       #f43f5e;
    --yellow:    #f59e0b;
    --green:     #22c55e;
    --blue:      #60a5fa;
    --purple:    #c084fc;
    --pink:      #e879f9;
    --glow:      rgba(139,92,246,0.15);
    --glow2:     rgba(139,92,246,0.05);
  }}

  * {{ box-sizing:border-box; margin:0; padding:0; }}
  html {{ scroll-behavior:smooth; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse 80% 50% at 50% -20%, rgba(139,92,246,0.12) 0%, transparent 70%),
      radial-gradient(ellipse 50% 40% at 80% 80%, rgba(168,139,250,0.06) 0%, transparent 60%);
  }}

  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width:6px; height:6px; }}
  ::-webkit-scrollbar-track {{ background: var(--surface); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius:3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}

  /* ── Layout ── */
  .container {{ max-width:1400px; margin:0 auto; padding:32px 24px; }}

  /* ── Header ── */
  .header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 40px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
  }}
  .header-left h1 {{
    font-size: 2rem;
    font-weight: 800;
    background: linear-gradient(135deg, #a78bfa 0%, #e879f9 50%, #60a5fa 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.03em;
    line-height: 1.1;
    margin-bottom: 6px;
  }}
  .header-left .subtitle {{
    color: var(--muted);
    font-size: 0.85rem;
    font-weight: 400;
  }}
  .header-meta {{
    display: flex;
    flex-direction: column;
    gap: 6px;
    align-items: flex-end;
  }}
  .meta-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.78rem;
    color: var(--muted);
  }}
  .meta-row strong {{ color: var(--text); font-weight: 500; }}

  /* ── Badges ── */
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }}
  .badge-hardened {{ background: rgba(34,197,94,0.15); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }}
  .badge-weak     {{ background: rgba(244,63,94,0.15); color: #f43f5e; border: 1px solid rgba(244,63,94,0.3); }}
  .badge-critical {{ background: rgba(244,63,94,0.12); color: var(--red); border: 1px solid rgba(244,63,94,0.25); }}
  .badge-high     {{ background: rgba(245,158,11,0.12); color: var(--yellow); border: 1px solid rgba(245,158,11,0.25); }}
  .badge-medium   {{ background: rgba(96,165,250,0.12); color: var(--blue); border: 1px solid rgba(96,165,250,0.25); }}
  .badge-low      {{ background: rgba(34,197,94,0.12); color: var(--green); border: 1px solid rgba(34,197,94,0.25); }}
  .badge-secure   {{ background: rgba(34,197,94,0.12); color: var(--green); }}
  .badge-bypass   {{ background: rgba(244,63,94,0.12); color: var(--red); }}
  .badge-partial  {{ background: rgba(245,158,11,0.12); color: var(--yellow); }}
  .badge-unknown  {{ background: rgba(96,165,250,0.12); color: var(--blue); }}

  /* ── Section titles ── */
  .section-title {{
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* ── Glass card ── */
  .card {{
    background: rgba(18,18,26,0.7);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s, box-shadow 0.2s;
  }}
  .card::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgba(139,92,246,0.04) 0%, transparent 60%);
    pointer-events: none;
  }}
  .card:hover {{
    border-color: var(--border2);
    box-shadow: 0 0 40px rgba(139,92,246,0.08);
  }}
  .card-glow {{
    box-shadow: 0 0 60px var(--glow), inset 0 1px 0 rgba(255,255,255,0.05);
    border-color: rgba(139,92,246,0.3);
  }}

  /* ── Stat cards ── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    text-align: center;
    padding: 20px 16px;
  }}
  .stat-value {{
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 6px;
    font-variant-numeric: tabular-nums;
  }}
  .stat-label {{
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
  }}

  /* ── Risk bar ── */
  .risk-bar-wrap {{
    margin: 10px 0 4px;
    background: var(--surface2);
    border-radius: 6px;
    height: 6px;
    overflow: hidden;
  }}
  .risk-bar {{
    height: 100%;
    border-radius: 6px;
    background: linear-gradient(90deg, var(--accent) 0%, {risk_color} 100%);
    transition: width 1.5s cubic-bezier(0.4,0,0.2,1);
    box-shadow: 0 0 12px {risk_color}80;
  }}

  /* ── Charts ── */
  .charts-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px,1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .chart-wrap {{ height: 240px; position: relative; }}
  .card h3 {{
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 16px;
  }}

  /* ── Toolbar ── */
  .toolbar {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 16px;
  }}
  .search {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 14px 8px 36px;
    border-radius: 10px;
    font-size: 0.82rem;
    width: 260px;
    outline: none;
    font-family: inherit;
    transition: border-color 0.2s, box-shadow 0.2s;
    position: relative;
  }}
  .search:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(139,92,246,0.15); }}
  .search-wrap {{ position: relative; }}
  .search-icon {{
    position: absolute;
    left: 11px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    font-size: 0.85rem;
    pointer-events: none;
  }}
  .filters {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 6px 14px;
    border-radius: 20px;
    cursor: pointer;
    font-size: 0.75rem;
    font-weight: 500;
    font-family: inherit;
    transition: all 0.15s;
  }}
  .filter-btn:hover {{ color: var(--text); border-color: var(--border2); }}
  .filter-btn.active {{
    background: linear-gradient(135deg, rgba(139,92,246,0.2), rgba(168,139,250,0.1));
    color: var(--accent2);
    border-color: var(--accent);
    box-shadow: 0 0 12px rgba(139,92,246,0.2);
  }}

  /* ── Table ── */
  .table-wrap {{
    border-radius: 16px;
    overflow: hidden;
    border: 1px solid var(--border);
    background: rgba(18,18,26,0.6);
    backdrop-filter: blur(20px);
  }}
  table {{ width:100%; border-collapse:collapse; font-size:0.8rem; }}
  thead {{ position:sticky; top:0; z-index:10; }}
  th {{
    background: rgba(10,10,15,0.95);
    backdrop-filter: blur(10px);
    color: var(--muted);
    text-align: left;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    transition: color 0.15s;
  }}
  th:hover {{ color: var(--accent2); }}
  th.sort-asc::after  {{ content: ' ↑'; color: var(--accent); }}
  th.sort-desc::after {{ content: ' ↓'; color: var(--accent); }}
  td {{
    padding: 11px 14px;
    border-bottom: 1px solid rgba(42,42,63,0.5);
    vertical-align: middle;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr.data-row {{ cursor: pointer; transition: background 0.1s; }}
  tr.data-row:hover td {{ background: rgba(139,92,246,0.06); }}
  tr.data-row.active td {{ background: rgba(139,92,246,0.1); }}

  /* ── Detail panel ── */
  tr.detail-row td {{
    background: rgba(10,10,15,0.8);
    padding: 0;
    border-bottom: 1px solid var(--border);
  }}
  .detail-inner {{
    padding: 20px 24px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }}
  .detail-block {{ display:flex; flex-direction:column; gap:8px; }}
  .detail-label {{
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 4px;
  }}
  pre {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--accent2);
    background: rgba(139,92,246,0.06);
    border: 1px solid rgba(139,92,246,0.15);
    border-radius: 8px;
    padding: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 180px;
    overflow-y: auto;
    line-height: 1.5;
  }}
  pre.response {{ color: var(--text); background: rgba(26,26,40,0.8); border-color: var(--border); }}

  /* ── CVSS bar in table ── */
  .cvss-bar {{
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .cvss-track {{
    flex: 1;
    height: 4px;
    background: var(--surface2);
    border-radius: 2px;
    overflow: hidden;
  }}
  .cvss-fill {{ height: 100%; border-radius: 2px; }}

  /* ── Footer ── */
  footer {{
    margin-top: 48px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--muted);
    font-size: 0.75rem;
  }}
  footer a {{ color: var(--accent2); text-decoration: none; }}
  footer a:hover {{ color: var(--purple); }}

  /* ── Animations ── */
  @keyframes fadeIn {{ from{{opacity:0;transform:translateY(8px)}} to{{opacity:1;transform:translateY(0)}} }}
  .animate-in {{ animation: fadeIn 0.3s ease forwards; }}

  /* ── Scrollable detail ── */
  .detail-row {{ display: none; }}
  .detail-row.open {{ display: table-row; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>🛡️ Vigilar</h1>
      <div class="subtitle">LLM Red-Team & Security Auditing Framework · OWASP LLM Top 10 v1.1</div>
    </div>
    <div class="header-meta">
      {hardened_badge}
      <div class="meta-row"><span>Provider</span><strong>{provider}</strong></div>
      <div class="meta-row"><span>Model</span><strong>{model}</strong></div>
      <div class="meta-row"><span>Date</span><strong>{datetime.now().strftime('%Y-%m-%d %H:%M')}</strong></div>
      <div class="meta-row"><span>Total Probes</span><strong>{total}</strong></div>
    </div>
  </div>

  <!-- Stats -->
  <div class="section-title">Overview</div>
  <div class="stats-grid">
    <div class="card stat-card card-glow">
      <div class="stat-value" style="color:{risk_color}">{risk_score}</div>
      <div class="stat-label">Risk Score / 10</div>
      <div class="risk-bar-wrap"><div class="risk-bar" id="riskBar" style="width:0%"></div></div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--yellow)">{avg_cvss}</div>
      <div class="stat-label">Avg CVSS</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--red)">{counts['CRITICAL_BYPASS']}</div>
      <div class="stat-label">Critical Bypasses</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--yellow)">{counts['PARTIAL_LEAK']}</div>
      <div class="stat-label">Partial Leaks</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--green)">{counts['SECURE']}</div>
      <div class="stat-label">Secure</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--blue)">{counts['UNKNOWN']}</div>
      <div class="stat-label">Unknown</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--red)">{max_cvss}</div>
      <div class="stat-label">Max CVSS</div>
    </div>
    <div class="card stat-card">
      <div class="stat-value" style="color:var(--text)">{total}</div>
      <div class="stat-label">Total Probes</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="section-title">Analytics</div>
  <div class="charts-grid">
    <div class="card"><h3>Results by Status</h3><div class="chart-wrap"><canvas id="statusChart"></canvas></div></div>
    <div class="card"><h3>Results by OWASP Category</h3><div class="chart-wrap"><canvas id="owaspChart"></canvas></div></div>
    <div class="card"><h3>Attack Technique Breakdown</h3><div class="chart-wrap"><canvas id="techniqueChart"></canvas></div></div>
    <div class="card"><h3>CVSS Score Distribution</h3><div class="chart-wrap"><canvas id="cvssChart"></canvas></div></div>
  </div>

  <!-- Table -->
  <div class="section-title">Findings</div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input class="search" id="searchBox" placeholder="Search findings…" oninput="renderTable()">
    </div>
    <div class="filters" id="filterBtns">
      <button class="filter-btn active" onclick="setFilter('all',this)">All ({total})</button>
      <button class="filter-btn" onclick="setFilter('CRITICAL_BYPASS',this)">🔴 Critical ({counts['CRITICAL_BYPASS']})</button>
      <button class="filter-btn" onclick="setFilter('PARTIAL_LEAK',this)">🟡 Partial ({counts['PARTIAL_LEAK']})</button>
      <button class="filter-btn" onclick="setFilter('UNKNOWN',this)">🔵 Unknown ({counts['UNKNOWN']})</button>
      <button class="filter-btn" onclick="setFilter('SECURE',this)">🟢 Secure ({counts['SECURE']})</button>
    </div>
  </div>

  <div class="table-wrap">
    <table id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortBy(0)">#</th>
          <th onclick="sortBy(1)">OWASP</th>
          <th onclick="sortBy(2)">Category</th>
          <th onclick="sortBy(3)">Technique</th>
          <th onclick="sortBy(4)">Engine</th>
          <th onclick="sortBy(5)">Severity</th>
          <th onclick="sortBy(6)">CVSS</th>
          <th onclick="sortBy(7)">Status</th>
          <th onclick="sortBy(8)">Guard</th>
          <th onclick="sortBy(9)">Time</th>
        </tr>
      </thead>
      <tbody id="tableBody"></tbody>
    </table>
  </div>

  <footer>
    Vigilar &nbsp;·&nbsp; OWASP LLM Top 10 v1.1 &nbsp;·&nbsp;
    For security research and educational purposes only &nbsp;·&nbsp;
    <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank">OWASP LLM Top 10</a>
  </footer>
</div>

<script>
const DATA = {records_json};

const STATUS_BADGE = {{
  SECURE:          '<span class="badge badge-secure">🟢 Secure</span>',
  PARTIAL_LEAK:    '<span class="badge badge-partial">🟡 Partial</span>',
  CRITICAL_BYPASS: '<span class="badge badge-bypass">🔴 Critical</span>',
  UNKNOWN:         '<span class="badge badge-unknown">🔵 Unknown</span>',
}};
const SEV_BADGE = {{
  CRITICAL: '<span class="badge badge-critical">CRITICAL</span>',
  HIGH:     '<span class="badge badge-high">HIGH</span>',
  MEDIUM:   '<span class="badge badge-medium">MEDIUM</span>',
  LOW:      '<span class="badge badge-low">LOW</span>',
}};
const CVSS_COLOR = s => s>=7?'#f43f5e':s>=4?'#f59e0b':'#22c55e';

let activeFilter = 'all';
let sortCol = 0, sortAsc = true;
let openRow = null;

function renderTable() {{
  const tbody  = document.getElementById('tableBody');
  const search = document.getElementById('searchBox').value.toLowerCase();
  tbody.innerHTML = '';

  let filtered = DATA.filter(r => {{
    const matchF = activeFilter === 'all' || r.status === activeFilter;
    const matchS = !search || JSON.stringify(r).toLowerCase().includes(search);
    return matchF && matchS;
  }});

  // sort
  filtered.sort((a,b) => {{
    const keys = ['','owasp_id','category','technique','engine','severity','cvss_score','status','guard','elapsed'];
    const k = keys[sortCol];
    if (!k) return 0;
    const va = a[k] ?? '', vb = b[k] ?? '';
    return sortAsc ? (va>vb?1:va<vb?-1:0) : (va<vb?1:va>vb?-1:0);
  }});

  // update th classes
  document.querySelectorAll('th').forEach((th,i) => {{
    th.classList.remove('sort-asc','sort-desc');
    if (i===sortCol) th.classList.add(sortAsc?'sort-asc':'sort-desc');
  }});

  filtered.forEach((r,i) => {{
    const c  = CVSS_COLOR(r.cvss_score);
    const tr = document.createElement('tr');
    tr.className = 'data-row';
    tr.innerHTML = `
      <td style="color:var(--muted)">${{i+1}}</td>
      <td><strong style="color:var(--accent2)">${{r.owasp_id}}</strong></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${{r.category}}</td>
      <td style="font-size:0.72rem;color:var(--purple)">${{r.technique}}</td>
      <td style="font-size:0.72rem;color:var(--muted)">${{r.engine}}/${{r.variant}}</td>
      <td>${{SEV_BADGE[r.severity]||r.severity}}</td>
      <td>
        <div class="cvss-bar">
          <span style="font-weight:700;color:${{c}};min-width:28px">${{r.cvss_score}}</span>
          <div class="cvss-track"><div class="cvss-fill" style="width:${{r.cvss_score*10}}%;background:${{c}}"></div></div>
        </div>
      </td>
      <td>${{STATUS_BADGE[r.status]||r.status}}</td>
      <td style="font-size:0.72rem;color:${{r.guard==='UNSAFE'?'var(--red)':r.guard==='SAFE'?'var(--green)':'var(--muted)'}}">${{r.guard}}</td>
      <td style="font-size:0.72rem;color:var(--muted)">${{r.elapsed}}s</td>
    `;

    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.innerHTML = `<td colspan="10">
      <div class="detail-inner">
        <div class="detail-block">
          <div class="detail-label">Analysis</div>
          <div style="color:var(--text);font-size:0.8rem;padding:8px 0">${{r.description}}</div>
          <div class="detail-label" style="margin-top:8px">Adversarial Probe</div>
          <pre>${{r.prompt}}</pre>
        </div>
        <div class="detail-block">
          <div class="detail-label">Model Response</div>
          <pre class="response">${{r.response}}</pre>
        </div>
      </div>
    </td>`;

    tr.onclick = () => {{
      if (openRow && openRow !== detail) {{
        openRow.classList.remove('open');
        openRow.previousSibling?.classList.remove('active');
      }}
      detail.classList.toggle('open');
      tr.classList.toggle('active');
      openRow = detail.classList.contains('open') ? detail : null;
    }};

    tbody.appendChild(tr);
    tbody.appendChild(detail);
  }});
}}

function setFilter(val, btn) {{
  activeFilter = val;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}}

function sortBy(col) {{
  if (sortCol === col) sortAsc = !sortAsc;
  else {{ sortCol = col; sortAsc = true; }}
  renderTable();
}}

renderTable();

// Animate risk bar on load
setTimeout(() => {{
  document.getElementById('riskBar').style.width = '{risk_score*10}%';
}}, 300);

// ── Charts ───────────────────────────────────────────────────────
const chartDef = {{
  plugins: {{ legend: {{ labels: {{ color:'#7070a0', font:{{size:11}} }} }} }},
  scales: {{
    x: {{ ticks:{{color:'#7070a0',font:{{size:10}}}}, grid:{{color:'rgba(42,42,63,0.6)'}} }},
    y: {{ ticks:{{color:'#7070a0',font:{{size:10}}}}, grid:{{color:'rgba(42,42,63,0.6)'}} }},
  }},
}};

// Status doughnut
new Chart(document.getElementById('statusChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Secure','Partial Leak','Critical Bypass','Unknown'],
    datasets: [{{
      data: [{counts['SECURE']},{counts['PARTIAL_LEAK']},{counts['CRITICAL_BYPASS']},{counts['UNKNOWN']}],
      backgroundColor: ['rgba(34,197,94,0.8)','rgba(245,158,11,0.8)','rgba(244,63,94,0.8)','rgba(96,165,250,0.8)'],
      borderWidth: 0,
      hoverOffset: 6,
    }}],
  }},
  options: {{
    cutout: '68%',
    plugins: {{
      legend: {{ labels: {{ color:'#7070a0', font:{{size:11}}, padding:16 }} }},
    }},
  }},
}});

// OWASP bar
const owaspLabels = {json.dumps(list(owasp_counts.keys()))};
const owaspBypass = {json.dumps([owasp_counts[k]['CRITICAL_BYPASS'] for k in owasp_counts])};
const owaspPartial= {json.dumps([owasp_counts[k]['PARTIAL_LEAK'] for k in owasp_counts])};
const owaspSecure = {json.dumps([owasp_counts[k]['SECURE'] for k in owasp_counts])};
new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: owaspLabels,
    datasets: [
      {{ label:'Critical', data:owaspBypass, backgroundColor:'rgba(244,63,94,0.7)', borderColor:'#f43f5e', borderWidth:1 }},
      {{ label:'Partial',  data:owaspPartial,backgroundColor:'rgba(245,158,11,0.7)',borderColor:'#f59e0b',borderWidth:1 }},
      {{ label:'Secure',   data:owaspSecure, backgroundColor:'rgba(34,197,94,0.4)', borderColor:'#22c55e', borderWidth:1 }},
    ],
  }},
  options: {{ ...chartDef, plugins:{{ legend:{{ labels:{{ color:'#7070a0',font:{{size:10}} }} }} }},
    scales:{{ x:{{ stacked:true, ticks:{{color:'#7070a0',font:{{size:9}}}}, grid:{{color:'rgba(42,42,63,0.6)'}} }},
              y:{{ stacked:true, ticks:{{color:'#7070a0'}}, grid:{{color:'rgba(42,42,63,0.6)'}} }} }} }},
}});

// Technique bar
const techLabels = {json.dumps(list(tech_counts.keys()))};
const techVals   = {json.dumps(list(tech_counts.values()))};
new Chart(document.getElementById('techniqueChart'), {{
  type: 'bar',
  data: {{
    labels: techLabels,
    datasets: [{{ label:'Probes', data:techVals,
      backgroundColor: techLabels.map((_,i) => `hsla(${{(i*47)%360}},70%,60%,0.7)`),
      borderWidth: 0, borderRadius: 4,
    }}],
  }},
  options: {{ ...chartDef, indexAxis:'y',
    plugins:{{ legend:{{ display:false }} }},
    scales:{{ x:{{ ticks:{{color:'#7070a0'}}, grid:{{color:'rgba(42,42,63,0.6)'}} }},
              y:{{ ticks:{{color:'#7070a0',font:{{size:9}}}}, grid:{{display:false}} }} }} }},
}});

// CVSS distribution
const cvssData = {json.dumps(cvss_scores)};
const cvssGroups = [0,0,0,0,0];
cvssData.forEach(s => {{ if(s<2)cvssGroups[0]++; else if(s<4)cvssGroups[1]++; else if(s<7)cvssGroups[2]++; else if(s<9)cvssGroups[3]++; else cvssGroups[4]++; }});
new Chart(document.getElementById('cvssChart'), {{
  type: 'bar',
  data: {{
    labels: ['0–2','2–4','4–7','7–9','9–10'],
    datasets: [{{ label:'Findings', data:cvssGroups, borderRadius:6, borderWidth:0,
      backgroundColor:['rgba(34,197,94,0.7)','rgba(34,197,94,0.7)','rgba(245,158,11,0.7)','rgba(244,63,94,0.7)','rgba(244,63,94,0.9)'],
    }}],
  }},
  options: {{ ...chartDef, plugins:{{ legend:{{ display:false }} }} }},
}});
</script>
</body>
</html>"""

    html_path = output_path.replace(".md",".html")
    os.makedirs(os.path.dirname(html_path) if os.path.dirname(html_path) else ".", exist_ok=True)
    with open(html_path,"w",encoding="utf-8") as f:
        f.write(html)
    print(f"  {C.GREEN}✔{C.RESET}  HTML Dashboard → {C.WHITE}{os.path.abspath(html_path)}{C.RESET}")