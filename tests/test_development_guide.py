"""Offline edition generation, evidence binding and content-safety boundaries."""
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_development_guide as guide


class PageInventory(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.fragment_links = []
        self.asset_sources = []
        self.external_scripts = []
        self.article_count = 0

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "article":
            self.article_count += 1
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.fragment_links.append(attrs["href"][1:])
        if tag == "img":
            self.asset_sources.append(attrs.get("src", ""))
        if tag == "script" and "src" in attrs:
            self.external_scripts.append(attrs["src"])


class GuideTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        destination = root / "docs/development"
        shutil.copytree(guide.ROOT / "docs/development", destination)
        return root

    def test_complete_offline_navigation_and_source_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            report = guide.build(root / "derived/guide", root)
            raw = (root / "derived/guide/index.html").read_bytes()
            page = PageInventory()
            page.feed(raw.decode("utf-8"))
            self.assertEqual(page.article_count, len(guide.CHAPTER_NAMES))
            self.assertTrue(set(page.fragment_links).issubset(page.ids))
            self.assertFalse(page.external_scripts)
            self.assertEqual(set(page.asset_sources), set(guide.ASSET_NAMES))
            self.assertFalse(report["network_required"])
            self.assertFalse(report["camera_operations"])
            self.assertEqual(report["html_sha256"], guide.sha(raw))
            for record in report["chapters"]:
                self.assertEqual(record["sha256"], guide.sha((root / record["source"]).read_bytes()))
            self.assertIn("No current development-readiness", raw.decode("utf-8"))

    def test_readiness_is_bound_to_exact_record_and_changes_edition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "evidence").mkdir()
            evidence = root / "evidence/development-readiness.json"
            evidence.write_text(json.dumps({"code_ready": False, "notes": "<script>alert(1)</script>"}))
            first = guide.build(root / "derived/first", root)
            self.assertEqual(first["readiness_sha256"], guide.sha(evidence.read_bytes()))
            page = (root / "derived/first/index.html").read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
            self.assertNotIn("<script>alert(1)</script>", page)
            evidence.write_text(json.dumps({"code_ready": False, "notes": "New observed failure"}))
            second = guide.build(root / "derived/second", root)
            self.assertNotEqual(first["readiness_sha256"], second["readiness_sha256"])
            self.assertNotEqual(first["html_sha256"], second["html_sha256"])
            self.assertEqual(first["chapters"], second["chapters"])

    def test_markdown_html_and_executable_links_are_not_promoted(self):
        source = guide.ROOT / "docs/development/README.md"
        rendered = guide.render_markdown('<script>bad()</script>\n\n[run](javascript:bad)\n\n![x](https://example.com/image.png)', source, guide.ROOT)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("javascript:", rendered)
        self.assertNotIn('<img', rendered)
        self.assertNotIn("https://example.com", rendered)

    def test_active_svg_rejected_before_any_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "docs/development/architecture.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>bad()</script></svg>')
            with self.assertRaisesRegex(ValueError, "active content"):
                guide.build(root / "derived/guide", root)
            self.assertFalse((root / "derived/guide").exists())

    def test_output_boundaries_preserve_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            existing = root / "derived/guide"
            existing.mkdir(parents=True)
            (existing / "keep.txt").write_text("keep")
            with self.assertRaises(FileExistsError):
                guide.build(existing, root)
            self.assertEqual((existing / "keep.txt").read_text(), "keep")
            with self.assertRaisesRegex(ValueError, "derived"):
                guide.build(root / "publish", root)
            self.assertFalse((root / "publish").exists())

    def test_broken_fence_or_readiness_fails_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            chapter = root / "docs/development/01-start-here.md"
            original = chapter.read_text(encoding="utf-8")
            chapter.write_text(original + "\n```python\nunclosed")
            with self.assertRaisesRegex(ValueError, "Unclosed code fence"):
                guide.build(root / "derived/one", root)
            self.assertFalse((root / "derived/one").exists())
            chapter.write_text(original, encoding="utf-8")
            (root / "evidence").mkdir()
            (root / "evidence/development-readiness.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                guide.build(root / "derived/two", root)
            self.assertFalse((root / "derived/two").exists())


if __name__ == "__main__":
    unittest.main()
