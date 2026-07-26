# Contributing · 贡献指南

skillxray is only as good as its rules. Found an attack pattern it misses, or a
false positive it trips on? That's the most valuable PR you can send.

skillxray 的价值全在规则里。发现了它漏掉的攻击手法，或者踩到的误报？那就是最有
价值的 PR。

## The two-sided contract · 双向约定

Every change must keep **both** sides true:

1. **No false negatives** — known-malicious skills must be caught.
2. **No false positives** — genuinely clean skills (including security docs that
   *quote* attack strings) must stay quiet.

`tests/fixtures/` holds the golden set for both. `tests/test_skillxray.py`
enforces it, and CI runs `skillxray scan anthropics/skills` mentally in the same
spirit — the official skills must never grade below A for a security reason.

## Add a detection rule · 新增一条检测规则

Rules live in one place: the `RULES` list in [`skillxray.py`](skillxray.py).
Each is a small dict.

Pattern rule (a regex over the skill's text):

```python
dict(id="SXR0XX", severity="HIGH", kind="pattern", target="any_text",
     pattern=r"your-distinctive-regex",
     flags="i",
     title_en="What it is", title_zh="是什么",
     advice_en="What to do about it.", advice_zh="该怎么办。"),
```

- `severity`: `CRITICAL | HIGH | MEDIUM | LOW | INFO`.
- `target`: `any_text | skill_md | body | frontmatter | scripts`.
- `pattern` must compile in **both** Python `re` and JavaScript `RegExp` (the
  site reuses it): no inline `(?i)` — use `flags="i"`; no possessive quantifiers;
  no `\p{...}` classes.
- A pattern must never match the empty string.

Builtin rule (a named check implemented in code): add the entry with
`kind="builtin", check="your-check"`, then implement `your-check` in
`run_builtin_rule` (Python) and — if it should run on the site — in the
`runBuiltin` switch in [`docs/scanner.js`](docs/scanner.js).

## Then · 然后

```bash
python build_web.py            # regenerate docs/rules.js from RULES
python tests/test_skillxray.py # all tests must pass
```

Add a fixture that exercises your rule:

- a malicious skill under `tests/fixtures/evil-*/SKILL.md` that your rule catches, or
- a benign one it must *not* flag (these are just as important).

Then a test asserting the grade / fired rule. Open the PR.

## Rules of thumb · 一些原则

- **Prefer precision over recall for CRITICAL/HIGH.** A noisy scanner gets
  muted. If a pattern needs context to be dangerous, score it MEDIUM and explain.
- **Mind the use–mention line.** If your pattern could match a security doc
  quoting the bad thing, make sure `is_mention` / the fixtures cover it.
- **Advice must be actionable and bilingual.** Tell the reader what to do, in
  both `_en` and `_zh`.
- **Never suggest running the dangerous thing.** Advice is for the human
  reviewing the skill.

Thanks for helping people trust their agents' skills a little less blindly. 🔎
