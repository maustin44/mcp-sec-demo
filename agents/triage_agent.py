import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
DOCS = REPO_ROOT / "docs"
DOCS.mkdir(exist_ok=True)

def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def severity_score(sev: str) -> int:
    s = (sev or "").lower()
    if "critical" in s: return 100
    if "high" in s: return 80
    if "medium" in s: return 50
    if "low" in s: return 20
    return 10

def semgrep_findings(data):
    findings = []
    if not data or "results" not in data:
        return findings
    for r in data["results"]:
        path = r.get("path")
        start = r.get("start", {}).get("line")
        msg = r.get("extra", {}).get("message", "Semgrep finding")
        sev = r.get("extra", {}).get("severity", "MEDIUM")
        rule = r.get("check_id", "unknown-rule")
        # Simple noise filter example
        if path and ("node_modules/" in path or path.endswith(".md")):
            continue
        findings.append({
            "tool": "semgrep",
            "title": f"{rule}: {msg}",
            "severity": sev,
            "location": f"{path}:{start}" if path and start else (path or "unknown"),
            "recommendation": "Review code context and apply secure coding fix where applicable."
        })
    return findings

def gitleaks_findings(data):
    findings = []
    if not data:
        return findings
    # gitleaks JSON is usually an array
    if isinstance(data, list):
        for r in data:
            findings.append({
                "tool": "gitleaks",
                "title": f"Secret detected: {r.get('Description','Secret')}",
                "severity": "CRITICAL",
                "location": f"{r.get('File','unknown')}:{r.get('StartLine','')}",
                "recommendation": "Remove secret, rotate credentials, and add secret scanning pre-commit/CI checks."
            })
    return findings

def osv_findings(data):
    findings = []
    if not data:
        return findings
    vulns = data.get("results", [])
    for res in vulns:
        pkgs = res.get("packages", [])
        for p in pkgs:
            pkg_name = p.get("package", {}).get("name", "unknown")
            vulns_list = p.get("vulnerabilities", [])
            for v in vulns_list:
                vid = v.get("id", "OSV")
                severity = "HIGH"  # OSV varies; keep simple for MVP
                findings.append({
                    "tool": "osv-scanner",
                    "title": f"Vulnerable dependency: {pkg_name} ({vid})",
                    "severity": severity,
                    "location": "dependency-manifest",
                    "recommendation": "Update dependency to a fixed version and validate application behavior."
                })
    return findings

def main():
    semgrep = load_json(REPORTS / "semgrep.json")
    gitleaks = load_json(REPORTS / "gitleaks.json")
    osv = load_json(REPORTS / "osv.json")

    findings = []
    findings += gitleaks_findings(gitleaks)
    findings += osv_findings(osv)
    findings += semgrep_findings(semgrep)

    # Sort by severity
    findings.sort(key=lambda f: severity_score(f.get("severity")), reverse=True)

    md = []
    md.append("# Fix List (Prioritized)")
    md.append("")
    md.append(f"- Generated: {datetime.utcnow().isoformat()}Z")
    md.append(f"- Total findings: {len(findings)}")
    md.append("")

    if not findings:
        md.append("No findings detected.")
    else:
        for i, f in enumerate(findings, start=1):
            md.append(f"## {i}. {f['title']}")
            md.append(f"- Tool: `{f['tool']}`")
            md.append(f"- Severity: **{f['severity']}**")
            md.append(f"- Location: `{f['location']}`")
            md.append(f"- Recommendation: {f['recommendation']}")
            md.append("")

    out = DOCS / "FIX_LIST.md"
    out.write_text("\n".join(md), encoding="utf-8")
    print(f"Wrote {out}")

if __name__ == "__main__":
    main()