import os
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parents[1]

def detect_languages(root: Path):
    exts = {}
    for p in root.rglob("*"):
        if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts:
            ext = p.suffix.lower()
            if ext:
                exts[ext] = exts.get(ext, 0) + 1
    # Rough mapping
    lang_map = {
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".py": "Python",
        ".json": "JSON",
        ".md": "Markdown",
        ".yml": "YAML",
        ".yaml": "YAML",
    }
    langs = {}
    for ext, count in exts.items():
        lang = lang_map.get(ext)
        if lang:
            langs[lang] = langs.get(lang, 0) + count
    return sorted(langs.items(), key=lambda x: x[1], reverse=True)

def find_entrypoints(root: Path):
    entrypoints = []
    candidates = [
        root / "app" / "server.js",
        root / "app" / "app.js",
        root / "app" / "index.js",
        root / "package.json",
    ]
    for c in candidates:
        if c.exists():
            entrypoints.append(str(c.relative_to(root)))
    return entrypoints

def write_catalog():
    docs_dir = REPO_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    langs = detect_languages(REPO_ROOT)
    entrypoints = find_entrypoints(REPO_ROOT)

    md = []
    md.append("# Repository Catalog")
    md.append("")
    md.append(f"- Generated: {datetime.utcnow().isoformat()}Z")
    md.append(f"- Repo Root: `{REPO_ROOT.name}`")
    md.append("")

    md.append("## Languages (approx.)")
    if langs:
        for lang, count in langs:
            md.append(f"- {lang}: {count} files")
    else:
        md.append("- (No languages detected)")
    md.append("")

    md.append("## Key Entry Points")
    if entrypoints:
        for e in entrypoints:
            md.append(f"- `{e}`")
    else:
        md.append("- (No obvious entrypoints found)")
    md.append("")

    md.append("## Important Directories")
    for d in ["app", "agents", "reports", "docs", ".github/workflows"]:
        if (REPO_ROOT / d).exists():
            md.append(f"- `{d}/`")
    md.append("")

    out_path = docs_dir / "CATALOG.md"
    out_path.write_text("\n".join(md), encoding="utf-8")
    print(f"Wrote {out_path}")

if __name__ == "__main__":
    write_catalog()