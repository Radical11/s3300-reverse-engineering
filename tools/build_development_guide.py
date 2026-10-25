"""Build the offline S3300 handbook from source chapters and current evidence.

The HTML contains no remote assets, server dependency or firmware action. This
renderer intentionally supports the repository's small Markdown subset rather
than executing embedded HTML. Generated editions stay under ignored derived/.
"""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CHAPTER_NAMES = ("README.md", "01-start-here.md", "02-setup.md", "03-architecture.md",
                 "04-find-a-feature.md", "05-resource-tutorials.md", "06-amber.md",
                 "07-sdk.md", "08-build-and-package.md", "09-camera-tests.md",
                 "10-recovery-and-troubleshooting.md", "11-interface-reference.md")
ASSET_NAMES = ("architecture.svg", "address-spaces.svg")
TOKEN = re.compile(r"(`[^`\n]+`|!\[[^\]]*\]\([^)]+\)|\[[^\]]+\]\([^)]+\)|\*\*[^*\n]+\*\*)")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def chapter_id(name):
    return "chapter-" + Path(name).stem.lower()


def local_link(target, source, root):
    """Resolve documentation links without allowing executable URL schemes."""
    if target.startswith("https://"):
        return target
    if target.startswith("#"):
        return target
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("//"):
        return None
    relative, separator, anchor = target.partition("#")
    resolved = (source.parent / relative).resolve()
    if not resolved.is_relative_to(root.resolve()):
        return None
    if resolved.parent == source.parent and resolved.name in CHAPTER_NAMES:
        return "#" + chapter_id(resolved.name)
    # Nonchapter repository references remain useful in the local checkout.
    return resolved.as_uri() + (("#" + anchor) if separator else "")


def render_inline(text, source, root):
    result = []
    for piece in TOKEN.split(text):
        if not piece:
            continue
        if piece.startswith("`") and piece.endswith("`"):
            result.append("<code>" + html.escape(piece[1:-1]) + "</code>")
        elif piece.startswith("**") and piece.endswith("**"):
            result.append("<strong>" + render_inline(piece[2:-2], source, root) + "</strong>")
        elif piece.startswith("!["):
            match = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", piece)
            alt, target = match.groups()
            if target in ASSET_NAMES:
                result.append('<img class="diagram" src="' + html.escape(target, quote=True)
                              + '" alt="' + html.escape(alt, quote=True) + '">')
            else:
                result.append(html.escape(alt + " (image omitted from offline edition)"))
        elif piece.startswith("["):
            match = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", piece)
            label, target = match.groups()
            href = local_link(target, source, root)
            result.append(('<a href="' + html.escape(href, quote=True) + '">' + html.escape(label) + '</a>')
                          if href is not None else html.escape(label))
        else:
            result.append(html.escape(piece))
    return "".join(result)


def render_markdown(text, source, root):
    lines = text.splitlines()
    result = []
    index = 0
    paragraph = []
    list_kind = None

    def flush():
        if paragraph:
            result.append("<p>" + render_inline(" ".join(paragraph), source, root) + "</p>")
            paragraph.clear()

    def close_list():
        nonlocal list_kind
        if list_kind:
            result.append("</" + list_kind + ">")
            list_kind = None

    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            flush()
            close_list()
            language = re.sub(r"[^a-zA-Z0-9_-]", "", line[3:].strip())
            code = []
            index += 1
            while index < len(lines) and not lines[index].startswith("```"):
                code.append(lines[index])
                index += 1
            if index == len(lines):
                raise ValueError(f"Unclosed code fence in {source.name}")
            result.append('<pre><code data-language="' + language + '">' + html.escape("\n".join(code)) + "</code></pre>")
        elif re.match(r"^#{1,6} ", line):
            flush()
            close_list()
            level = min(6, len(line) - len(line.lstrip("#")) + 1)
            result.append(f"<h{level}>" + render_inline(line.lstrip("# "), source, root) + f"</h{level}>")
        elif line.startswith("|"):
            flush()
            close_list()
            rows = []
            while index < len(lines) and lines[index].startswith("|"):
                cells = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    rows.append(cells)
                index += 1
            index -= 1
            if rows:
                result.append('<div class="table-wrap"><table><thead><tr>' + "".join("<th>" + render_inline(cell, source, root) + "</th>" for cell in rows[0]) + "</tr></thead><tbody>")
                for row in rows[1:]:
                    result.append("<tr>" + "".join("<td>" + render_inline(cell, source, root) + "</td>" for cell in row) + "</tr>")
                result.append("</tbody></table></div>")
        elif re.match(r"^(?:[-*] |\d+\. )", line):
            flush()
            kind = "ol" if re.match(r"^\d+\.", line) else "ul"
            if list_kind != kind:
                close_list()
                result.append("<" + kind + ">")
                list_kind = kind
            result.append("<li>" + render_inline(re.sub(r"^(?:[-*] |\d+\. )", "", line), source, root) + "</li>")
        elif not line.strip():
            flush()
            close_list()
        else:
            close_list()
            paragraph.append(line.strip())
        index += 1
    flush()
    close_list()
    return "\n".join(result)


def verify_svg(data):
    tree = ET.fromstring(data)
    if tree.tag.rsplit("}", 1)[-1] != "svg":
        raise ValueError("Guide diagram is not SVG")
    forbidden = {"script", "foreignObject", "iframe", "image", "use", "style"}
    for element in tree.iter():
        if element.tag.rsplit("}", 1)[-1] in forbidden:
            raise ValueError("Guide SVG contains external or active content")
        for key, value in element.attrib.items():
            name = key.rsplit("}", 1)[-1].lower()
            if name.startswith("on") or name in ("href", "src") or "url(http" in value.lower():
                raise ValueError("Guide SVG contains an external or executable reference")


def load_status(root):
    path = root / "evidence/development-readiness.json"
    if not path.exists():
        return {"source": None, "sha256": None, "data": {
            "status": "No current development-readiness record was available when this edition was built.",
            "resource_ready": "unknown", "code_ready": "unknown", "recovery_verified": "unknown",
            "next_step": "Run s3300.py readiness --json and rebuild the guide. Absence is not a pass."}}
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Readiness evidence must be a JSON object")
    return {"source": "evidence/development-readiness.json", "sha256": sha(raw), "data": value}


CSS = """
:root{color-scheme:light dark;--ink:#183047;--paper:#fff;--muted:#506477;--line:#d7e0e8;--back:#f1f5f9;--accent:#14637d}
*{box-sizing:border-box}body{margin:0;background:var(--back);color:var(--ink);font:16px/1.65 system-ui,Segoe UI,sans-serif}
.layout{display:grid;grid-template-columns:270px minmax(0,1fr);max-width:1600px;margin:auto}
aside{padding:24px 18px;position:sticky;top:0;height:100vh;overflow:auto;border-right:1px solid var(--line)}
main{min-width:0;padding:30px 42px 80px;max-width:1180px}article,.status{background:var(--paper);padding:26px 32px;border:1px solid var(--line);border-radius:14px;margin:0 0 28px;scroll-margin-top:15px}
h1,h2,h3{line-height:1.2;letter-spacing:-.02em}h1{font-size:2.2rem;margin-top:0}h2{font-size:1.8rem;margin-top:.3em}h3{font-size:1.25rem;margin-top:1.8em}
a{color:var(--accent)}nav a{display:block;padding:8px 4px;text-decoration:none;font-size:.93rem}nav a:hover{text-decoration:underline}
input{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--paper);color:var(--ink);font:inherit}
.small{font-size:.83rem;color:var(--muted)}code{font: .9em/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}p code,td code{background:var(--back);padding:1px 4px;border-radius:4px}
pre{overflow:auto;padding:17px;background:#112b3c;color:#f2f7fa;border-radius:8px;white-space:pre;font-size:.9rem}pre code{overflow-wrap:normal}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{padding:10px 12px;border:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--back)}
.diagram{display:block;max-width:100%;height:auto;margin:24px 0}.badge{display:inline-block;background:var(--back);padding:3px 9px;border-radius:20px;font-size:.82rem}details pre{max-height:350px}
[hidden]{display:none!important}.no-results{padding:25px;background:var(--paper)}
@media(max-width:850px){.layout{display:block}aside{position:static;height:auto;border:0;border-bottom:1px solid var(--line)}nav{columns:2}main{padding:20px 12px}article,.status{padding:20px}h1{font-size:1.9rem}}
@media(prefers-color-scheme:dark){:root{--ink:#deebf3;--paper:#152a39;--muted:#a8bbc8;--line:#385064;--back:#0e202e;--accent:#8ed6e8}}
@media print{aside,input,.status details{display:none}.layout{display:block}main{max-width:none;padding:0}article{break-before:page;border:0}a{color:inherit}pre{white-space:pre-wrap}body{background:white;color:black}}
"""
SCRIPT = """
const search = document.getElementById('search');
const articles = [...document.querySelectorAll('article[data-chapter]')];
const links = [...document.querySelectorAll('nav a')];
search.addEventListener('input', () => {
  const words = search.value.toLowerCase().trim().split(/\\s+/).filter(Boolean);
  let count = 0;
  for (const article of articles) {
    const visible = words.every(word => article.textContent.toLowerCase().includes(word));
    article.hidden = !visible;
    if (visible) count++;
    const link = links.find(item => item.hash === '#' + article.id);
    if (link) link.hidden = !visible;
  }
  document.getElementById('no-results').hidden = count !== 0;
  document.getElementById('search-status').textContent = words.length ? count + ' chapters match' : 'Search stays on this computer';
});
"""


def build(output, root=ROOT):
    root, output = root.resolve(), output.resolve()
    if not output.is_relative_to(root / "derived"):
        raise ValueError("Generated guide must stay under ignored derived/")
    if output.exists():
        raise FileExistsError("Choose a new guide output directory")
    source_dir = root / "docs/development"
    chapters = []
    for name in CHAPTER_NAMES:
        source = source_dir / name
        raw = source.read_bytes()
        text = raw.decode("utf-8")
        title = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), name)
        chapters.append({"source": source, "name": name, "title": title,
                         "sha256": sha(raw), "html": render_markdown(text, source, root)})
    assets = {}
    for name in ASSET_NAMES:
        data = (source_dir / name).read_bytes()
        verify_svg(data)
        assets[name] = data
    status = load_status(root)
    nav = "\n".join('<a href="#' + chapter_id(c["name"]) + '">' + html.escape(c["title"]) + '</a>' for c in chapters)
    articles = "\n".join('<article data-chapter="true" id="' + chapter_id(c["name"]) + '">' + c["html"] + '</article>' for c in chapters)
    status_html = html.escape(json.dumps(status["data"], indent=2, ensure_ascii=False))
    readiness_badges = []
    for key, label in (("resource_ready", "Resource-ready"), ("code_ready", "Code-ready")):
        value = status["data"].get(key)
        state = "Verified" if value is True else "Not ready" if value is False else "Unknown"
        readiness_badges.append('<span class="badge">' + label + ': ' + state + '</span>')
    document = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' data:; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
                '<title>S3300 developer handbook</title><style>' + CSS + '</style></head><body>'
                '<div class="layout"><aside><strong>S3300 development</strong><p class="small">Offline handbook · evidence-bound</p>'
                '<label for="search">Search chapters</label><input id="search" type="search" placeholder="buffer ownership, Amber…">'
                '<p class="small" id="search-status" aria-live="polite">Search stays on this computer</p><nav aria-label="Chapters">' + nav + '</nav></aside><main>'
                '<header><h1>Make the camera your own.</h1><p>Understand one contract. Build a bounded change. Verify the result.</p></header>'
                '<section class="status" aria-label="Readiness evidence"><span class="badge">Evidence at build time</span><h2>Current readiness</h2>'
                + ' '.join(readiness_badges) +
                '<p>This edition embeds the ledger available when it was built. Rebuild after new results; absent evidence is not a pass.</p>'
                '<details><summary>Read the exact readiness record</summary><pre><code>' + status_html + '</code></pre></details>'
                '<p class="small">Source: ' + html.escape(status["source"] or "No record available") + '</p></section>'
                '<p id="no-results" class="no-results" hidden>No chapters match those words. Try fewer terms.</p>'
                + articles + '<footer class="small">Generated from versioned guide sources. No camera or firmware operation is available from this page.</footer>'
                '</main></div><script>' + SCRIPT + '</script></body></html>')
    # Validate every source before creating an output tree, then use exclusive files.
    output.mkdir(parents=True)
    for name, data in assets.items():
        with (output / name).open("xb") as handle:
            handle.write(data)
    with (output / "index.html").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(document)
    manifest = {"schema_version": 1, "artifact": "offline-development-guide", "network_required": False,
                "camera_operations": False, "entry": "index.html", "html_sha256": sha(document.encode("utf-8")),
                "chapters": [{"source": "docs/development/" + c["name"], "title": c["title"], "sha256": c["sha256"]} for c in chapters],
                "assets": {name: sha(data) for name, data in assets.items()},
                "readiness_source": status["source"], "readiness_sha256": status["sha256"],
                "limitations": ["A guide build does not establish runtime behavior or recovery.",
                                "Readiness is the retained build-time record; regenerate after new evidence.",
                                "Links to other repository evidence require the local checkout; chapters and diagrams are standalone offline."]}
    with (output / "manifest.json").open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New local directory under derived/")
    args = parser.parse_args(argv)
    report = build(args.output)
    print(json.dumps({"entry": str(args.output.resolve() / "index.html"), "chapters": len(report["chapters"]),
                      "network_required": False, "camera_operations": False,
                      "readiness_source": report["readiness_source"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
