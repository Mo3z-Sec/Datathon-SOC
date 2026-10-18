"""Static checks that need no web framework: the dashboard only calls routes that exist,
and the front-end source avoids unsafe patterns."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS = (ROOT / "soc" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "soc" / "static" / "index.html").read_text(encoding="utf-8")
MAIN = (ROOT / "soc" / "main.py").read_text(encoding="utf-8")


def route_patterns():
    pats = []
    for m in re.finditer(r'@app\.(get|post)\("([^"]+)"', MAIN):
        pats.append(re.compile("^" + re.sub(r"\{\w+\}", r"[^/]+", m.group(2)) + "$"))
    return pats


class FrontendContract(unittest.TestCase):
    def test_every_api_path_used_by_the_dashboard_exists(self):
        paths = set(re.findall(r"['\"`](/api/[A-Za-z0-9_./-]+)", JS))
        self.assertGreater(len(paths), 10)
        pats = route_patterns()
        for p in paths:
            probe = p.rstrip("/")
            self.assertTrue(any(r.match(probe) or r.match(probe + "1") for r in pats), f"no route for {p}")

    def test_no_unsafe_dom_or_eval(self):
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(bad, JS, bad)

    def test_page_loads_nothing_from_other_origins(self):
        self.assertIsNone(re.search(r"(src|href)=\"https?://", HTML))
        self.assertNotIn("https://", JS.replace("https://api.anthropic.com", ""))
        self.assertNotIn("<script>", HTML.replace('<script src="/static/app.js"></script>', ""))  # no inline scripts (CSP)

    def test_simulated_banner_is_in_the_page(self):
        self.assertIn("SIMULATED DATA", HTML)

    def test_every_element_id_the_script_needs_exists_in_html_or_is_created(self):
        for el in ("banner", "login-view", "login-form", "token-input", "login-error", "app-view", "nav", "auto-refresh",
                   "role-badge", "ai-badge", "logout-btn", "main", "drawer", "modal", "toasts"):
            self.assertIn(f'id="{el}"', HTML, el)

    def test_mutating_routes_require_analyst(self):
        for m in re.finditer(r'@app\.post\("([^"]+)"\)\s+def \w+\(([^)]*)\)', MAIN):
            self.assertIn("analyst_only", m.group(2), m.group(1))


if __name__ == "__main__":
    unittest.main()
