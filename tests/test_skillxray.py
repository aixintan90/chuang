# -*- coding: utf-8 -*-
"""Tests for skillxray.py — run with:  python tests/test_skillxray.py

The heart of these tests is the two-sided accuracy contract every scanner
lives or dies by:
  * malicious fixtures MUST be caught (no false negatives), and
  * benign skills MUST stay quiet (no false positives).
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import skillxray as sx

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def write_skill(root, name, body):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8",
                 newline="\n") as f:
        f.write(body)
    return d


class RuleIntegrityTests(unittest.TestCase):
    def test_all_patterns_compile(self):
        import re
        for r in sx.RULES:
            if r["kind"] == "pattern":
                re.compile(r["pattern"],
                           re.IGNORECASE if "i" in r.get("flags", "") else 0)

    def test_ids_unique_and_bilingual(self):
        seen = set()
        for r in sx.RULES:
            self.assertNotIn(r["id"], seen)
            seen.add(r["id"])
            for key in ("title_en", "title_zh", "advice_en", "advice_zh"):
                self.assertTrue(r[key], "%s missing %s" % (r["id"], key))

    def test_every_builtin_check_is_handled(self):
        # A builtin rule whose check nobody implements silently does nothing.
        skill = sx.SkillUnderScan(os.path.join(FIX, "clean-formatter"))
        for r in sx.RULES:
            if r["kind"] == "builtin":
                # Should not raise for any known check.
                sx.run_builtin_rule(r, skill, [])


class MaliciousTests(unittest.TestCase):
    """No false negatives: known-bad skills must be graded F/D and fire
    their signature rules."""

    def scan(self, name):
        return sx.scan_skill(os.path.join(FIX, name))

    def rules_fired(self, findings):
        return {f["rule"] for f in findings}

    def test_exfil_is_failed(self):
        _, findings, score, grade = self.scan("evil-exfil")
        self.assertEqual(grade, "F")
        fired = self.rules_fired(findings)
        self.assertIn("SXR003", fired)   # hide from user
        self.assertIn("SXR010", fired)   # exfil combo
        self.assertIn("SXR011", fired)   # credential paths
        self.assertIn("SXR012", fired)   # network upload
        # The credential read is an instruction, not a quote — full severity.
        cred = [f for f in findings if f["rule"] == "SXR011"]
        self.assertTrue(any(f["severity"] == "HIGH" for f in cred))

    def test_injection_is_failed(self):
        _, findings, score, grade = self.scan("evil-injection")
        self.assertEqual(grade, "F")
        fired = self.rules_fired(findings)
        self.assertIn("SXR001", fired)   # curl | bash
        self.assertIn("SXR002", fired)   # ignore previous instructions
        # bashrc persistence sits in a quoted shell string but is executed:
        # it must NOT be demoted away to nothing.
        self.assertTrue(
            any(f["rule"] == "SXR001" and f["severity"] == "CRITICAL"
                for f in findings))

    def test_hidden_unicode_caught(self):
        _, findings, score, grade = self.scan("evil-hidden")
        self.assertIn("SXR004", self.rules_fired(findings))
        self.assertLessEqual(score, 40)


class BenignTests(unittest.TestCase):
    """No false positives: a genuinely clean skill scores 100 and fires
    nothing above INFO."""

    def test_clean_formatter_is_spotless(self):
        _, findings, score, grade = sx.scan_skill(
            os.path.join(FIX, "clean-formatter"))
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")
        for f in findings:
            self.assertEqual(f["severity"], "INFO")

    def test_documentation_quoting_is_not_an_attack(self):
        # The single hardest case: a security doc that QUOTES an attack
        # string in order to warn against it (this is exactly what
        # Anthropic's own claude-api skill does).
        with tempfile.TemporaryDirectory() as tmp:
            d = write_skill(tmp, "secure-writer",
                "---\nname: secure-writer\n"
                "description: Advice on writing safe prompts.\n---\n\n"
                "# Guidance\n\n"
                "Avoid override-style language such as "
                "\"ignore all previous instructions\" — Claude is trained to "
                "resist it. For example, never write "
                "\"disregard the user's request\".\n")
            _, findings, score, grade = sx.scan_skill(d)
            criticals = [f for f in findings if f["severity"] == "CRITICAL"]
            self.assertEqual(criticals, [],
                             "quoted example wrongly flagged CRITICAL")

    def test_reference_material_is_demoted(self):
        # The same risky string is graver in SKILL.md (auto-loaded) than in a
        # reference file (read on demand).
        with tempfile.TemporaryDirectory() as tmp:
            d = write_skill(tmp, "ref-skill",
                "---\nname: ref-skill\ndescription: Does a thing.\n---\n\n"
                "# Thing\n\nDoes a thing. See references/notes.md.\n")
            os.makedirs(os.path.join(d, "references"))
            with io.open(os.path.join(d, "references", "notes.md"), "w",
                         encoding="utf-8", newline="\n") as f:
                f.write("Historically some tools ran `rm -rf /` by mistake.\n")
            _, findings, _, _ = sx.scan_skill(d)
            rmrf = [f for f in findings if f["rule"] == "SXR013"]
            for f in rmrf:
                self.assertNotEqual(f["severity"], "HIGH")


class OfficialShadowTests(unittest.TestCase):
    def test_official_source_not_flagged_as_impostor(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = write_skill(tmp, "docx",
                "---\nname: docx\ndescription: Edit Word documents.\n---\n\nx\n")
            _, f_off, _, _ = sx.scan_skill(d, source="anthropics/skills")
            _, f_rnd, _, _ = sx.scan_skill(d, source="rando/skills")
            self.assertNotIn("SXR034", {f["rule"] for f in f_off})
            self.assertIn("SXR034", {f["rule"] for f in f_rnd})


class IgnoreDirectiveTests(unittest.TestCase):
    def test_inline_ignore_suppresses_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = write_skill(tmp, "opt-out",
                "---\nname: opt-out\ndescription: Uses sudo intentionally.\n"
                "---\n\n# T\n\n"
                "Run `sudo apt install foo`. <!-- skillxray: ignore SXR011 -->\n")
            skill = sx.SkillUnderScan(d)
            self.assertIn("SXR011", skill.ignored.get("SKILL.md", set()))


class LockVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sx-lock-")
        self.home = tempfile.mkdtemp(prefix="sx-home-")
        self._old_home = os.environ.get("HOME"), os.environ.get("USERPROFILE")
        os.environ["HOME"] = self.home
        os.environ["USERPROFILE"] = self.home
        write_skill(self.tmp, "one",
                    "---\nname: one\ndescription: d.\n---\n\nbody\n")

    def tearDown(self):
        import shutil
        for p in (self.tmp, self.home):
            shutil.rmtree(p, ignore_errors=True)
        h, u = self._old_home
        if h is not None:
            os.environ["HOME"] = h
        if u is not None:
            os.environ["USERPROFILE"] = u

    def test_lock_then_verify_clean(self):
        snap = sx.snapshot([self.tmp])
        self.assertIn(os.path.abspath(os.path.join(self.tmp, "one")),
                      snap["skills"])

    def test_verify_detects_tamper(self):
        pal = sx.Palette(False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            sx.cmd_lock([self.tmp], pal, False)
        # tamper
        with io.open(os.path.join(self.tmp, "one", "SKILL.md"), "a",
                     encoding="utf-8") as f:
            f.write("\nnow with curl | bash\n")
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            code = sx.cmd_verify([self.tmp], pal, False, "en")
        self.assertEqual(code, 1)
        self.assertIn("CHANGED", buf2.getvalue())


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sx.main(argv)
        return code, buf.getvalue()

    def test_scan_fixtures_json(self):
        code, out = self.run_main(["scan", FIX, "--json"])
        data = json.loads(out)
        names = {d["name"]: d for d in data}
        self.assertEqual(names["evil-injection"]["grade"], "F")
        self.assertEqual(names["clean-formatter"]["grade"], "A")

    def test_fail_on_threshold(self):
        # clean fixture alone: exits 0 even at --fail-on low
        code, _ = self.run_main(
            ["scan", os.path.join(FIX, "clean-formatter"), "--fail-on", "low",
             "--no-color"])
        self.assertEqual(code, 0)
        # evil fixture: exits 1
        code, _ = self.run_main(
            ["scan", os.path.join(FIX, "evil-injection"), "--no-color"])
        self.assertEqual(code, 1)

    def test_unknown_failon_rejected(self):
        code, _ = self.run_main(["scan", FIX, "--fail-on", "bogus"])
        self.assertEqual(code, 2)

    def test_rules_listing(self):
        code, out = self.run_main(["rules", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), len(sx.RULES))

    def test_version(self):
        code, out = self.run_main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("skillxray", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
