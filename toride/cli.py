import argparse
import sys

from toride.fuzzer import load_decide_fn, run_fuzz_test
from toride.report import (
    generate_json_report,
    generate_markdown_report,
    generate_pdf_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Toride Fuzz: Determine agent vulnerability to prompt injection and tool-call hijacking."
    )
    parser.add_argument(
        "target",
        help="Target decision function in format 'module:function' or 'module.function'",
    )
    parser.add_argument(
        "--json",
        default="toride_report.json",
        help="Output path for the JSON report (default: toride_report.json)",
    )
    parser.add_argument(
        "--pdf",
        default="toride_report.pdf",
        help="Output path for the PDF report (default: toride_report.pdf)",
    )
    parser.add_argument(
        "--markdown",
        default="toride_report.md",
        help="Output path for the Markdown report (default: toride_report.md)",
    )

    args = parser.parse_args()

    print(f"[*] Loading decision function from: {args.target}")
    try:
        decide_fn = load_decide_fn(args.target)
    except Exception as e:
        print(f"[-] Failed to load target: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] Running penetration fuzz test against agent decision function...")
    results = run_fuzz_test(decide_fn)

    total = len(results)
    blocked_count = sum(1 for r in results if r["blocked"])
    hijacked_count = sum(1 for r in results if r["hijacked"])
    passed_count = total - hijacked_count
    pass_rate = (passed_count / total) * 100 if total > 0 else 100.0

    print("\n==============================================")
    print("      TORIDE AGENT FUZZ TEST SUMMARY          ")
    print("==============================================")
    print(f"Total Payloads Run:     {total}")
    print(f"Blocked by AgentGuard:  {blocked_count}")
    print(f"Successfully Hijacked:  {hijacked_count}")
    print(f"Overall Pass Rate:      {pass_rate:.1f}%")
    print("==============================================")

    print(f"\n[*] Saving JSON report to {args.json}...")
    generate_json_report(results, args.json)

    print(f"[*] Saving Markdown report to {args.markdown}...")
    generate_markdown_report(results, args.markdown)

    print(f"[*] Attempting to save PDF report to {args.pdf}...")
    try:
        generate_pdf_report(results, args.pdf)
    except Exception as e:
        print(f"[-] PDF generation skipped/failed: {e}")


if __name__ == "__main__":
    main()
