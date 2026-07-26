// skillxray in-browser scanner engine.
// A faithful port of skillxray.py's engine for a single pasted SKILL.md.
// Rule DATA comes from rules.js (generated from skillxray.py); this file
// mirrors the scanning LOGIC. Keep the two engines in step.
(function (global) {
  "use strict";

  var DATA = global.SKILLXRAY || {};
  var SEVERITIES = DATA.severities || ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var SEV_SCORE = DATA.sevScore || {};
  var RULES = DATA.rules || [];
  var ALLOW = DATA.urlAllowlist || [];
  var OFFICIAL = DATA.officialNames || [];

  function sevIndex(s) { return SEVERITIES.indexOf(s); }
  function demote(sev, steps) {
    var i = Math.min(SEVERITIES.length - 1, sevIndex(sev) + (steps || 1));
    return SEVERITIES[i];
  }

  // --- text helpers -------------------------------------------------------
  function lineOf(text, idx) {
    return (text.slice(0, idx).match(/\n/g) || []).length + 1;
  }
  function excerptAt(text, idx, width) {
    width = width || 90;
    var start = text.lastIndexOf("\n", idx - 1) + 1;
    var end = text.indexOf("\n", idx);
    if (end === -1) end = text.length;
    var line = text.slice(start, end).trim();
    if (line.length > width) line = line.slice(0, width) + "…";
    return line;
  }

  function stripBom(t) { return t.replace(/^﻿/, ""); }

  function parseFrontmatter(text) {
    text = stripBom(text);
    var m = text.match(/^\s*---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
    if (!m) return { front: "", body: text, fields: {} };
    var front = m[1], body = m[2], fields = {}, key = null;
    front.split("\n").forEach(function (line) {
      var s = line.trim();
      var kv = s.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$/);
      if (kv && s.indexOf("- ") !== 0) { key = kv[1].toLowerCase(); fields[key] = kv[2].trim(); }
      else if (key && s) { fields[key] = (fields[key] + " " + s).trim(); }
    });
    return { front: front, body: body, fields: fields };
  }

  // --- use / mention distinction (mirrors is_mention in Python) ----------
  var MENTION_WORDS = /\b(avoid|avoids|avoiding|never|don'?t|do not|instead of|rather than|example|examples|e\.g\.|such as|like this|anti-?pattern|bad practice|malicious|attack|attacker|injection|exploit|suspicious|red flag|detect|detects|detecting|scanner|warning sign|beware|watch out|避免|不要|切勿|例如|比如|恶意|攻击|注入|反面)\b/i;
  var COMMAND_LINE = /^\s*(#|\/\/|\*|>)?\s*(sudo\s+)?(echo|printf|cat|curl|wget|iwr|irm|Invoke-\w+|bash|sh|zsh|eval|exec|python\d?|node|npm|npx|pip\d?|go|cargo|gem|tee|chmod|rm)\b|[|;&]{1,2}\s*(sudo\s+)?(ba|z)?sh\b|\|\s*iex\b|>>\s*["']?[~/$]/i;

  function inCodeContext(text, start, end) {
    var before = text.slice(0, start);
    var fences = (before.match(/\n```/g) || []).length;
    if (fences % 2 === 1 || before.indexOf("```") === 0) return true;
    var lineStart = before.lastIndexOf("\n") + 1;
    var lineEnd = text.indexOf("\n", end);
    var line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
    var rel = start - lineStart;
    var ticks = (line.slice(0, rel).match(/`/g) || []).length;
    return ticks % 2 === 1;
  }

  function isMention(text, start, end) {
    var lineStart = text.lastIndexOf("\n", start - 1) + 1;
    var lineEnd = text.indexOf("\n", end);
    var physical = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
    var left = text.slice(Math.max(0, start - 160), start);
    var right = text.slice(end, end + 80);
    var lq = left.split("\n").pop();
    var rq = right.split("\n")[0];
    if (MENTION_WORDS.test(lq + " " + rq)) return true;
    if (COMMAND_LINE.test(physical)) return false;
    if (inCodeContext(text, start, end)) return false;
    var pairs = [['"', '"'], ["'", "'"], ["“", "”"], ["「", "」"]];
    for (var i = 0; i < pairs.length; i++) {
      if (lq.slice(-40).indexOf(pairs[i][0]) !== -1 &&
          rq.slice(0, 40).indexOf(pairs[i][1]) !== -1) return true;
    }
    return false;
  }

  // --- rule engine --------------------------------------------------------
  function jsFlags(rule) { return rule.flags && rule.flags.indexOf("i") !== -1 ? "gi" : "g"; }

  function targetTexts(skill, target) {
    switch (target) {
      case "skill_md": return [["SKILL.md", skill.text]];
      case "frontmatter": return [["frontmatter", skill.front]];
      case "body": return [["SKILL.md", skill.body]];
      case "scripts": return [];  // single pasted file has no bundled scripts
      case "any_text": return [["SKILL.md", skill.text]];
      default: return [["SKILL.md", skill.text]];
    }
  }

  function mk(rule, where, line, excerpt, severity, note) {
    return {
      rule: rule.id, severity: severity || rule.severity,
      title_en: rule.title_en, title_zh: rule.title_zh,
      advice_en: rule.advice_en, advice_zh: rule.advice_zh,
      file: where, line: line, excerpt: excerpt, note: note || ""
    };
  }

  function runPattern(rule, skill) {
    var out = [], rx;
    try { rx = new RegExp(rule.pattern, jsFlags(rule)); }
    catch (e) { return out; }
    targetTexts(skill, rule.target).forEach(function (pair) {
      var where = pair[0], text = pair[1];
      if (!text) return;
      var seen = {}, m, guard = 0;
      rx.lastIndex = 0;
      while ((m = rx.exec(text)) && guard < 5000) {
        guard++;
        if (m.index === rx.lastIndex) rx.lastIndex++;
        if (!m[0] || !m[0].trim()) continue;
        var ln = lineOf(text, m.index);
        if (seen[ln]) continue;
        seen[ln] = 1;
        var sev = rule.severity, note = "";
        if (isMention(text, m.index, m.index + m[0].length)) {
          sev = demote(rule.severity, 2); note = "quoted/discussed, not issued";
        }
        out.push(mk(rule, where, ln, excerptAt(text, m.index), sev, note));
        if (Object.keys(seen).length >= 3) break;
      }
    });
    return out;
  }

  var ZERO_WIDTH = "​‌‍⁠﻿";
  var BIDI = "‪‫‬‭‮⁦⁧⁨⁩";

  function domainAllowed(d) {
    d = d.toLowerCase().replace(/\.$/, "");
    return ALLOW.some(function (a) { return d === a || d.slice(-(a.length + 1)) === "." + a; });
  }

  function runBuiltin(rule, skill, all) {
    var out = [], text = skill.text, m;
    switch (rule.check) {
      case "unicode-hidden":
        var bad = [];
        for (var i = 0; i < text.length; i++) {
          var ch = text[i];
          if (ZERO_WIDTH.indexOf(ch) !== -1 || BIDI.indexOf(ch) !== -1) bad.push([i, ch]);
        }
        if (bad.length) out.push(mk(rule, "SKILL.md", lineOf(text, bad[0][0]),
          bad.length + " invisible char(s), first U+" +
          bad[0][1].charCodeAt(0).toString(16).toUpperCase()));
        break;
      case "exfil-combo":
        var ids = {}; all.forEach(function (f) { ids[f.rule] = 1; });
        if (ids["SXR011"] && ids["SXR012"])
          out.push(mk(rule, "(skill-wide)", 0, "credential paths + network upload both present"));
        break;
      case "hidden-html-comments":
        var re = /<!--([\s\S]*?)-->/g;
        while ((m = re.exec(text))) {
          var inner = m[1].trim();
          if (inner.length > 60 && /\b(you|must|always|never|do|run|execute|send|write)\b/i.test(inner))
            out.push(mk(rule, "SKILL.md", lineOf(text, m.index), inner.slice(0, 80) + "…"));
        }
        break;
      case "base64-blob":
        m = text.match(/[A-Za-z0-9+/]{200,}={0,2}/);
        if (m) out.push(mk(rule, "SKILL.md", lineOf(text, text.indexOf(m[0])), m[0].length + "-char blob"));
        break;
      case "url-audit":
        var fetchy = /(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|fetch\(|requests\.\w+\(|urlopen\(|axios\.\w+\(|http\.get|src\s*=|href\s*=)[^\n]{0,120}?https?:\/\/([A-Za-z0-9.-]+)/gi;
        var doms = {};
        while ((m = fetchy.exec(text))) {
          var d = m[2].toLowerCase().replace(/\.$/, "");
          if (!domainAllowed(d) && !doms[d]) doms[d] = lineOf(text, m.index);
        }
        Object.keys(doms).sort().slice(0, 5).forEach(function (d) {
          out.push(mk(rule, "SKILL.md", doms[d], d));
        });
        break;
      case "image-exfil":
        var badgeHosts = ["shields.io", "img.shields.io", "badgen.net",
          "badge.fury.io", "codecov.io", "circleci.com", "travis-ci.org",
          "travis-ci.com", "appveyor.com", "coveralls.io", "snyk.io",
          "githubusercontent.com", "github.com", "gitlab.com"];
        var img = /!\[[^\]]*\]\(\s*(https?:\/\/([A-Za-z0-9.-]+)[^)\s]*)/g;
        while ((m = img.exec(text))) {
          var iurl = m[1], ihost = m[2].toLowerCase();
          if (iurl.indexOf("?") === -1) continue;
          if (badgeHosts.some(function (b) { return ihost === b || ihost.slice(-(b.length + 1)) === "." + b; })) continue;
          out.push(mk(rule, "SKILL.md", lineOf(text, m.index), iurl.slice(0, 90)));
          break;
        }
        break;
      case "desc-mismatch":
        var desc = (skill.fields.description || "").toLowerCase();
        var discloses = /network|internet|online|upload|send|post|fetch|download|api|request|url|web|http|server|cloud|remote|sync/.test(desc);
        var uploads = /(curl|wget)\s[^\n]*\s(-d|--data|--upload-file|-T|-F)\b|requests\.(post|put|patch)\(|\.upload\(|urlopen\([^\n]*data=|fetch\([^\n]*method:\s*['"]POST/i;
        if (desc && uploads.test(skill.body) && !discloses)
          out.push(mk(rule, "SKILL.md", 1, "uploads data but description doesn't mention it"));
        break;
      case "official-shadow":
        if (OFFICIAL.indexOf(skill.name) !== -1 &&
            OFFICIAL_SOURCES.indexOf((skill.source || "").toLowerCase()) === -1)
          out.push(mk(rule, "(directory name)", 0, skill.name));
        break;
      case "long-lines":
        var lines = text.split("\n");
        for (var j = 0; j < lines.length; j++) {
          if (lines[j].length > 1500) { out.push(mk(rule, "SKILL.md", j + 1, lines[j].length + " chars on one line")); break; }
        }
        break;
      case "frontmatter-hooks":
        if (skill.fields.hooks) out.push(mk(rule, "frontmatter", 1, "hooks: " + skill.fields.hooks.slice(0, 70)));
        break;
      case "frontmatter-tools":
        var tools = skill.fields["allowed-tools"] || "";
        if (/\bBash\b|\bShell\b|\bWrite\b/.test(tools)) out.push(mk(rule, "frontmatter", 1, "allowed-tools: " + tools.slice(0, 70)));
        break;
      case "frontmatter-angle":
        if (skill.front.indexOf("<") !== -1 || skill.front.indexOf(">") !== -1)
          out.push(mk(rule, "frontmatter", 1, "angle bracket in frontmatter"));
        break;
      case "size-audit":
        var n = text ? text.split("\n").length : 0;
        if (n > 500) out.push(mk(rule, "SKILL.md", n, n + " lines"));
        break;
      case "spec-format":
        var name = skill.fields.name || "";
        if (name && skill.name && name !== skill.name)
          out.push(mk(rule, "frontmatter", 1, "name '" + name + "' vs directory '" + skill.name + "'"));
        else if (name && !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name))
          out.push(mk(rule, "frontmatter", 1, "invalid name '" + name + "'"));
        break;
      // scripts-present, binaries-bundled: N/A for a single pasted SKILL.md
      default: break;
    }
    return out;
  }
  var OFFICIAL_SOURCES = ["anthropics/skills", "openai/skills", "agentskills/agentskills"];

  function scoreFindings(findings) {
    var charged = {};
    findings.forEach(function (f) {
      var w = charged[f.rule];
      if (w === undefined || sevIndex(f.severity) < sevIndex(w)) charged[f.rule] = f.severity;
    });
    var score = 100;
    Object.keys(charged).forEach(function (k) { score -= (SEV_SCORE[charged[k]] || 0); });
    return Math.max(0, score);
  }

  function grade(score, hasMd) {
    if (!hasMd) return "?";
    return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  }

  // --- public API ---------------------------------------------------------
  function scan(text, opts) {
    opts = opts || {};
    var fm = parseFrontmatter(text || "");
    var skill = {
      text: stripBom(text || ""), front: fm.front, body: fm.body, fields: fm.fields,
      name: opts.name || fm.fields.name || "", source: opts.source || ""
    };
    var findings = [];
    RULES.forEach(function (r) { if (r.kind === "pattern") findings = findings.concat(runPattern(r, skill)); });
    RULES.forEach(function (r) { if (r.kind === "builtin") findings = findings.concat(runBuiltin(r, skill, findings)); });
    findings.sort(function (a, b) {
      var d = sevIndex(a.severity) - sevIndex(b.severity);
      return d !== 0 ? d : a.rule < b.rule ? -1 : 1;
    });
    var hasMd = !!skill.text.trim();
    var score = scoreFindings(findings);
    var counts = {}; SEVERITIES.forEach(function (s) { counts[s] = 0; });
    findings.forEach(function (f) { counts[f.severity]++; });
    return { findings: findings, score: score, grade: grade(score, hasMd), counts: counts, fields: skill.fields };
  }

  global.skillxray = { scan: scan, rules: RULES, severities: SEVERITIES, version: DATA.version };
})(window);
