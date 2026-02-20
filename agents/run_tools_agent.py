import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

def run(cmd, allow_fail=False):
    print(f"\n$ {' '.join(cmd)}")
    try:
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        if not allow_fail:
            raise

def main():
    # Semgrep (SAST)
    import sys
    run([sys.executable, "-m", "semgrep", "--config", "p/ci", "--json", "-o", str(REPORTS / "semgrep.json")], allow_fail=True)

    # Gitleaks (secrets)
    run(["gitleaks", "detect", "--source", ".", "--report-format", "json", "--report-path", str(REPORTS / "gitleaks.json")],
        allow_fail=True)

    # OSV-Scanner (dependencies)
    run(["osv-scanner", "--recursive", "--format", "json", "--output", str(REPORTS / "osv.json"), "."], allow_fail=True)

if __name__ == "__main__":
    main()