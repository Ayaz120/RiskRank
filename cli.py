"""
cli.py
------
Command-line entry point for the Vulnerability Triage Assistant.

Usage:
    python cli.py init
    python cli.py ingest-nmap sample_data/sample_nmap.xml
    python cli.py ingest-manual sample_data/sample_findings.json
    python cli.py list
    python cli.py triage
    python cli.py show <id>
    python cli.py prioritize
    python cli.py rank
    python cli.py report
    python cli.py reset
"""

import sys
import models
from parsers.nmap_parser import parse_nmap_xml
from parsers.manual_parser import parse_manual_json


def cmd_init():
    models.init_db()
    print(f"Database initialized at {models.DB_PATH}")


def cmd_ingest_nmap(filepath):
    models.init_db()
    findings = parse_nmap_xml(filepath)
    for f in findings:
        models.insert_finding(
            source="nmap", title=f["title"], description=f["description"],
            asset=f["asset"], raw_data=f["raw_data"],
        )
    print(f"Ingested {len(findings)} findings from Nmap scan: {filepath}")


def cmd_ingest_manual(filepath):
    models.init_db()
    findings = parse_manual_json(filepath)
    for f in findings:
        models.insert_finding(
            source="manual", title=f["title"], description=f["description"],
            asset=f["asset"], raw_data=f["raw_data"],
            asset_criticality=f["asset_criticality"],
        )
    print(f"Ingested {len(findings)} findings from manual file: {filepath}")


def cmd_list():
    findings = models.get_all_findings()
    if not findings:
        print("No findings stored yet. Run an ingest command first.")
        return

    print(f"\n{'ID':<4} {'Source':<8} {'Status':<10} {'Asset':<35} Title")
    print("-" * 100)
    for f in findings:
        print(f"{f['id']:<4} {f['source']:<8} {f['status']:<10} {f['asset'][:33]:<35} {f['title']}")
    print(f"\nTotal: {len(findings)} findings\n")


def cmd_reset():
    models.init_db()
    models.clear_all()
    print("All findings cleared.")


def cmd_triage():
    from engine.triage_engine import triage_finding, warm_up_model, OLLAMA_HOST, MODEL
    import requests

    try:
        requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Could not connect to Ollama at {OLLAMA_HOST}")
        print("Make sure Ollama is installed and running:")
        print("  1. Install: https://ollama.com/download")
        print(f"  2. Pull the model: ollama pull {MODEL}")
        print("  3. Or start it manually with: ollama serve")
        sys.exit(1)

    models.init_db()
    findings = models.get_all_findings(status="new")

    if not findings:
        print("No new findings to triage. Ingest something first, "
              "or everything may already be triaged (check with 'list').")
        return

    print(f"Warming up '{MODEL}' (loading into memory — can take a while "
          f"on the first run, especially without a dedicated GPU)...")
    try:
        warm_up_model()
        print("Model loaded.\n")
    except Exception as e:
        print(f"Warm-up failed: {e}")
        print("Continuing anyway — the first finding below may still be slow.\n")

    print(f"Triaging {len(findings)} findings with local model '{MODEL}'...\n")

    for f in findings:
        print(f"  [{f['id']}] {f['title']} ...", end=" ", flush=True)
        try:
            result = triage_finding(f)
            models.update_triage(
                finding_id=f["id"],
                explanation=result["explanation"],
                cvss_score=result["cvss_score"],
                cvss_reasoning=result["cvss_reasoning"],
                exploitability=result["exploitability"],
                remediation=result["remediation"],
            )
            print(f"done (CVSS {result['cvss_score']})")
        except Exception as e:
            print(f"FAILED ({e})")

    print("\nTriage complete. Run 'python cli.py prioritize' next.")


def cmd_show(finding_id):
    f = models.get_finding(finding_id)
    if not f:
        print(f"No finding with ID {finding_id}")
        return

    print(f"\n{'='*70}")
    print(f"[{f['id']}] {f['title']}")
    print(f"{'='*70}")
    print(f"Asset:        {f['asset']}")
    print(f"Source:       {f['source']}")
    print(f"Status:       {f['status']}")
    print(f"Description:  {f['description']}")

    if f["status"] in ("triaged", "scored"):
        print(f"\n--- AI Triage ---")
        print(f"Explanation:      {f['ai_explanation']}")
        print(f"CVSS Score:       {f['ai_cvss_score']}")
        print(f"CVSS Reasoning:   {f['ai_cvss_reasoning']}")
        print(f"Exploitability:   {f['ai_exploitability']}")
        print(f"Remediation:      {f['ai_remediation']}")
    else:
        print("\n(Not yet triaged — run 'python cli.py triage')")

    if f["status"] == "scored":
        print(f"\nPriority Score: {f['priority_score']} / 100  (rank #{f['priority_rank']})")

    print()


def cmd_prioritize():
    from scoring.prioritizer import prioritize_all_triaged

    ranked = prioritize_all_triaged()
    if not ranked:
        print("No triaged findings to prioritize. Run 'python cli.py triage' first.")
        return

    print(f"Prioritized {len(ranked)} findings. Run 'python cli.py rank' to view them.")


def cmd_rank():
    findings = models.get_all_findings(status="scored")
    if not findings:
        print("No prioritized findings yet. Run 'python cli.py prioritize' first.")
        return

    findings.sort(key=lambda f: f["priority_rank"])

    print(f"\n{'Rank':<5} {'Score':<7} {'CVSS':<6} {'Exploit.':<12} {'Crit.':<8} Title")
    print("-" * 100)
    for f in findings:
        print(f"{f['priority_rank']:<5} {f['priority_score']:<7} "
              f"{f['ai_cvss_score']:<6} {f['ai_exploitability']:<12} "
              f"{f['asset_criticality']:<8} {f['title']}")
    print()


def cmd_report():
    from reports.report_generator import generate_html_report

    findings = models.get_all_findings(status="scored")
    if not findings:
        print("No prioritized findings yet. Run 'triage' then 'prioritize' first.")
        return

    path = generate_html_report()
    print(f"Report generated: {path}")
    print("Open it in your browser to view the full write-up.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        cmd_init()
    elif command == "ingest-nmap":
        if len(sys.argv) < 3:
            print("Usage: python cli.py ingest-nmap <path-to-xml>")
            sys.exit(1)
        cmd_ingest_nmap(sys.argv[2])
    elif command == "ingest-manual":
        if len(sys.argv) < 3:
            print("Usage: python cli.py ingest-manual <path-to-json>")
            sys.exit(1)
        cmd_ingest_manual(sys.argv[2])
    elif command == "list":
        cmd_list()
    elif command == "reset":
        cmd_reset()
    elif command == "triage":
        cmd_triage()
    elif command == "show":
        if len(sys.argv) < 3:
            print("Usage: python cli.py show <finding-id>")
            sys.exit(1)
        cmd_show(int(sys.argv[2]))
    elif command == "prioritize":
        cmd_prioritize()
    elif command == "rank":
        cmd_rank()
    elif command == "report":
        cmd_report()
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
