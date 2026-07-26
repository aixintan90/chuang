#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
skillxray — X-ray your agent's skills before you trust them.
            技能安检机：SKILL.md 装进 Agent 之前，先过一遍安检。

Agent skills are instructions someone else wrote for YOUR agent. A malicious
skill can tell your agent to leak your SSH keys, pipe curl into bash, or
quietly rewrite its own permissions. skillxray is the `npm audit` of the
SKILL.md era: a zero-dependency static scanner + integrity lockfile.

Zero dependencies. Works offline. Python 3.9+.

Usage:
    skillxray scan                          scan every skill dir on this machine
    skillxray scan <path>                   scan one skill (or a folder of skills)
    skillxray scan owner/repo[/path]        scan a GitHub skill BEFORE installing
    skillxray lock                          write skillxray.lock (sha256 of every file)
    skillxray verify                        detect files changed since `lock`
    skillxray rules                         list all detection rules
    skillxray --json / --lang zh / --fail-on <sev>

Exit codes: 0 = clean (nothing at/above --fail-on), 1 = findings, 2 = usage.
"""

import hashlib
import io
import json
import os
import re
import sys
import tempfile
import zipfile

__version__ = "0.1.0"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_SCORE = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 7, "LOW": 2, "INFO": 0}

# Directories where agent tools discover skills (July 2026):
# Claude Code, Codex CLI, Gemini CLI, Cursor, Copilot/VS Code, opencode,
# plus the cross-tool convention ~/.agents/skills & .agents/skills.
USER_ROOTS = [
    "~/.claude/skills", "~/.agents/skills", "~/.cursor/skills",
    "~/.copilot/skills", "~/.gemini/skills", "~/.config/opencode/skills",
]
PROJECT_ROOTS = [
    ".claude/skills", ".agents/skills", ".cursor/skills",
    ".github/skills", ".gemini/skills", ".opencode/skills",
]

OFFICIAL_SKILL_NAMES = {
    "docx", "pdf", "pptx", "xlsx", "skill-creator", "mcp-builder",
    "claude-api", "webapp-testing", "web-artifacts-builder",
    "frontend-design", "canvas-design", "algorithmic-art",
    "brand-guidelines", "theme-factory", "slack-gif-creator",
}

URL_ALLOWLIST = (
    "github.com", "githubusercontent.com", "docs.claude.com",
    "code.claude.com", "agentskills.io", "anthropic.com", "claude.ai",
    "python.org", "developer.mozilla.org", "stackoverflow.com",
    "npmjs.com", "pypi.org", "crates.io", "golang.org", "go.dev",
    # Major CDNs: ubiquitous for fonts/libraries. Still worth reading, but a
    # payload host is far more likely to be somebody's VPS than jsdelivr.
    "cdnjs.cloudflare.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "unpkg.com", "jsdelivr.net", "cdn.tailwindcss.com",
    "example.com", "example.org", "localhost", "127.0.0.1", "0.0.0.0",
)

MAX_TEXT_BYTES = 512 * 1024      # per-file read cap for pattern scanning
BINARY_EXT = (".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".wasm",
              ".o", ".a", ".jar", ".class")
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".ts", ".rb",
              ".pl", ".cmd", ".bat")

# Legal boilerplate is full of URLs and scary-sounding words but is never the
# attack surface. Scanning it produced nothing but noise in testing.
BOILERPLATE_RE = re.compile(
    r"(^|/)(licen[cs]e|copying|notice|authors|contributors|changelog|"
    r"code_of_conduct|third[-_]party[-_]notices)"
    r"(\.(md|txt|rst))?$|-(ofl|apache|mit|license)\.txt$", re.IGNORECASE)

# Skills that get loaded into the agent's context automatically (SKILL.md)
# or executed (scripts) are the real attack surface. Reference material is
# read on demand and is far more likely to legitimately *discuss* dangerous
# strings, so findings there are reported one severity lower.
def demote(severity, steps=1):
    i = min(len(SEVERITIES) - 1, SEVERITIES.index(severity) + steps)
    return SEVERITIES[i]


# Repos whose skills are the originals, not impersonations of them.
OFFICIAL_SOURCES = {"anthropics/skills", "openai/skills", "agentskills/agentskills"}

IGNORE_RE = re.compile(r"skillxray:\s*ignore\s+([A-Z]{3}\d{3}(?:\s*,\s*[A-Z]{3}\d{3})*)",
                       re.IGNORECASE)

# The use–mention distinction, which is THE accuracy problem for this kind of
# scanner: security documentation quotes attack strings in order to warn about
# them. Anthropic's own claude-api skill lists "disregard the previous
# instruction" as an example of phrasing to avoid — flagging that as an attack
# is how a scanner earns a reputation for crying wolf. A match surrounded by
# quotation marks or by words that frame it as an example gets demoted two
# severity levels and labelled, rather than dropped: quoting is weak evidence
# of innocence, not proof.
MENTION_WORDS = re.compile(
    r"\b(avoid|avoids|avoiding|never|don'?t|do not|instead of|rather than|"
    r"example|examples|e\.g\.|such as|like this|anti-?pattern|bad practice|"
    r"malicious|attack|attacker|injection|exploit|suspicious|red flag|"
    r"detect|detects|detecting|scanner|warning sign|beware|watch out|"
    r"避免|不要|切勿|例如|比如|恶意|攻击|注入|反面)\b", re.IGNORECASE)


# A physical line that is itself a shell command: quoting inside it is string
# syntax, not "discussing an example". `echo 'curl … | sh' >> ~/.bashrc` is an
# attack being executed, even though the payload sits in single quotes.
COMMAND_LINE = re.compile(
    r"^\s*(#|//|\*|>)?\s*(sudo\s+)?"
    r"(echo|printf|cat|curl|wget|iwr|irm|Invoke-\w+|bash|sh|zsh|eval|exec|"
    r"python\d?|node|npm|npx|pip\d?|go|cargo|gem|tee|chmod|rm)\b"
    r"|[|;&]{1,2}\s*(sudo\s+)?(ba|z)?sh\b|\|\s*iex\b|>>\s*[\"']?[~/$]",
    re.IGNORECASE)


def in_code_context(text, start, end):
    """True when the match sits inside a fenced block or inline backticks.

    Quotes there are syntax — a JSON value like "bypassPermissions" or a shell
    string is code being handed to the agent, not prose quoting an example.
    """
    before = text[:start]
    if before.count("\n```") % 2 == 1 or before.startswith("```"):
        return True
    line_start = before.rfind("\n") + 1
    line = text[line_start:text.find("\n", end) if text.find("\n", end) != -1
                else len(text)]
    rel = start - line_start
    return line.count("`", 0, rel) % 2 == 1


def is_mention(text, start, end):
    """Heuristic: is this match being quoted/discussed rather than ISSUED?

    Two independent signals, deliberately conservative because a false
    "it's only an example" is how an attacker would sneak a real payload past
    the scanner:
      1. Framing words nearby (avoid, example, never, 比如 …) — strong, and
         applies everywhere.
      2. Real quotation marks around it IN PROSE — weak, and suppressed when
         the match is inside code (a shell command, a fenced block, or inline
         backticks), because quotes are string syntax there.
    Markdown backticks are never treated as quotation themselves: they format
    inline code, including paths in real instructions like "read `~/.ssh/id_rsa`".
    """
    physical_line = text[text.rfind("\n", 0, start) + 1:
                         text.find("\n", end) if text.find("\n", end) != -1
                         else len(text)]
    left = text[max(0, start - 160):start]
    right = text[end:end + 80]
    lq = left.rsplit("\n", 1)[-1]
    rq = right.split("\n", 1)[0]
    if MENTION_WORDS.search(lq + " " + rq):
        return True
    if COMMAND_LINE.search(physical_line):
        return False
    if in_code_context(text, start, end):
        return False
    for q in ('"', "'", "“", "「"):
        closer = {"“": "”", "「": "」"}.get(q, q)
        if q in lq[-40:] and closer in rq[:40]:
            return True
    return False

# ---------------------------------------------------------------------------
# Rule registry.
#
# This block is the single source of truth shared with the web scanner
# (docs/index.html). `skillxray rules --json` exports it; CI keeps the two
# in sync. Patterns must stay valid in BOTH Python `re` and JS `RegExp`
# (no inline (?i) — use "flags"; no possessive quantifiers; no \p classes).
#
# kind: "pattern" rules run a regex against the chosen target text.
#       "builtin" rules are implemented natively in both engines (same id).
# target: skill_md | body | frontmatter | scripts | any_text
# ---------------------------------------------------------------------------

RULES = [
    # ----------------------------------------------------------- CRITICAL
    dict(id="SXR001", severity="CRITICAL", kind="pattern", target="any_text",
         pattern=r"(curl|wget|iwr|irm|Invoke-WebRequest)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|(curl|wget|iwr|irm)[^\n|]*\|\s*iex\b",
         flags="i",
         title_en="Downloads a script and pipes it straight into a shell",
         title_zh="下载脚本并直接管道进 shell 执行（curl | bash）",
         advice_en="Never run remote code sight unseen. Download, read, then run.",
         advice_zh="绝不要盲执行远程代码。先下载、读完、再运行。"),
    dict(id="SXR002", severity="CRITICAL", kind="pattern", target="any_text",
         pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?)|disregard\s+(your|the|all)\s+(system|previous|safety)",
         flags="i",
         title_en="Tries to override the agent's prior instructions",
         title_zh="试图覆盖 Agent 的既有指令（越狱话术）",
         advice_en="Classic prompt-injection. A skill has no business overriding your agent's rules.",
         advice_zh="经典提示注入。正经技能没有任何理由要求 Agent 忽略原有规则。"),
    dict(id="SXR003", severity="CRITICAL", kind="pattern", target="any_text",
         pattern=r"(do\s+not|don'?t|never)\s+(tell|show|inform|mention|reveal)(\s+(this|it|that))?\s+(to\s+)?the\s+user|without\s+(telling|asking|informing|notifying)\s+the\s+user|hide\s+(this|it|these)\s+from\s+the\s+user",
         flags="i",
         title_en="Instructs the agent to hide actions from the user",
         title_zh="指示 Agent 向用户隐瞒其行为",
         advice_en="Anything a skill wants hidden from you is something you need to see.",
         advice_zh="凡是技能想瞒着你的事，恰恰就是你必须看到的事。"),
    dict(id="SXR004", severity="CRITICAL", kind="builtin", check="unicode-hidden",
         title_en="Hidden text: zero-width or bidirectional-override characters",
         title_zh="隐形文本：零宽字符或双向覆盖字符（肉眼不可见的指令通道）",
         advice_en="Invisible characters can smuggle instructions past human review. Inspect with a hex editor.",
         advice_zh="不可见字符可以把指令偷运过人工审查。用十六进制查看器检查。"),
    dict(id="SXR005", severity="CRITICAL", kind="pattern", target="any_text",
         pattern=r"(>>|tee\s+-a)\s*[\"']?~?/?\.(bashrc|zshrc|profile|bash_profile)|crontab\s+-|schtasks\s+/create|reg\s+add\s+HK|LaunchAgents|systemd.*enable",
         flags="i",
         title_en="Writes persistence: shell profiles, cron, scheduled tasks, registry",
         title_zh="植入持久化：改 shell 配置 / cron / 计划任务 / 注册表启动项",
         advice_en="A skill should never need to survive reboots or hook your shell startup.",
         advice_zh="一个技能不应该需要开机自启，也不应该钩住你的 shell 启动过程。"),
    # --------------------------------------------------------------- HIGH
    dict(id="SXR010", severity="HIGH", kind="builtin", check="exfil-combo",
         title_en="Reads credential paths AND uploads data in the same skill",
         title_zh="同一技能里既读取凭据路径、又存在网络上传",
         advice_en="The classic exfiltration shape. Treat as hostile until proven otherwise.",
         advice_zh="教科书级的数据外传形态。除非证明无害，否则按恶意处理。"),
    dict(id="SXR011", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|_netrc|\.npmrc|authorized_keys|/etc/shadow|(Login Data|Cookies)\b",
         flags="i",
         title_en="References credential / secret file paths",
         title_zh="引用了凭据或密钥文件路径（~/.ssh、.aws/credentials 等）",
         advice_en="Ask why a skill needs to know where your keys live.",
         advice_zh="问一句：这个技能为什么需要知道你的密钥放在哪？"),
    dict(id="SXR012", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"(curl|wget)\s[^\n]*\s(-d|--data(-binary|-raw|-urlencode)?|--upload-file|-T|-F|--form)\b|requests\.(post|put)\(|urllib\.request\.urlopen\([^\n]*data=",
         flags="i",
         title_en="Uploads data to the network",
         title_zh="存在向网络上传数据的行为",
         advice_en="Outbound data flows deserve a close look: what exactly is being sent, and where?",
         advice_zh="重点审查出站数据流：到底发了什么、发给了谁？"),
    dict(id="SXR013", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"rm\s+-\w*[rf]\w*\s+(/|~|\$HOME|\*)|del\s+/[fsq]\b|Remove-Item\s[^\n]*-Recurse[^\n]*-Force|mkfs\.|dd\s+if=",
         flags="i",
         title_en="Destructive filesystem commands on broad paths",
         title_zh="对大范围路径的破坏性命令（rm -rf / 格式化等）",
         advice_en="Legit skills operate on files they created, not on / or $HOME.",
         advice_zh="正经技能只动自己创建的文件，不会对 / 或 $HOME 下手。"),
    dict(id="SXR014", severity="HIGH", kind="pattern", target="scripts",
         pattern=r"(^|\s)sudo\s+",
         flags="",
         title_en="Bundled script uses sudo",
         title_zh="附带脚本中使用 sudo 提权",
         advice_en="No skill needs root. Ever.",
         advice_zh="没有任何技能需要 root 权限。一个都没有。"),
    # `.exec(` is RegExp.prototype.exec / subprocess handles — the danger is a
    # bare eval()/exec() on constructed input, so require no leading dot.
    dict(id="SXR015", severity="HIGH", kind="pattern", target="scripts",
         pattern=r"(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\(\s*[^)'\"]*(\+|%|\.format|f['\"]|\$\{)|Invoke-Expression|(?<![-\w.])iex\s|new\s+Function\s*\(",
         flags="i",
         title_en="Bundled script evaluates dynamic code",
         title_zh="附带脚本对动态内容执行 eval/exec",
         advice_en="eval of constructed strings is where hidden payloads detonate.",
         advice_zh="对拼接字符串做 eval，正是隐藏载荷起爆的地方。"),
    dict(id="SXR016", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"--dangerously-skip-permissions|--yolo\b|bypassPermissions|auto-?approve\s+(all|every)|acceptEdits",
         flags="i",
         title_en="Nudges the agent (or you) to disable permission prompts",
         title_zh="怂恿关闭权限确认（--dangerously-skip-permissions 等）",
         advice_en="A skill that wants your seatbelt off is planning a crash.",
         advice_zh="一个劝你解开安全带的技能，多半正准备撞车。"),
    dict(id="SXR017", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"(edit|modif\w*|append|add to|write to|update)[^\n]{0,60}(\.claude[/\\]settings|\.mcp\.json|managed-settings|settings\.local\.json)",
         flags="i",
         title_en="Wants to edit the agent's own configuration files",
         title_zh="试图修改 Agent 自身的配置文件（settings/.mcp.json）",
         advice_en="Config edits can grant permissions and add MCP servers. Review by hand.",
         advice_zh="改配置=发权限、加 MCP 服务器。必须人工审查。"),
    dict(id="SXR018", severity="HIGH", kind="builtin", check="hidden-html-comments",
         title_en="Substantial instructions hidden inside HTML comments",
         title_zh="HTML 注释里藏了大段指令（渲染时人眼看不到）",
         advice_en="Rendered Markdown hides HTML comments from humans — but not from the model.",
         advice_zh="Markdown 渲染后人看不见 HTML 注释——但模型看得见。"),
    dict(id="SXR019", severity="HIGH", kind="pattern", target="body",
         pattern=r"!`[^`\n]{2,}`",
         flags="",
         title_en="Dynamic context injection: shell command runs when skill loads",
         title_zh="动态上下文注入：技能加载时即执行 shell 命令（!`cmd`）",
         advice_en="Claude Code executes !`...` at invocation time. Read every one of these commands.",
         advice_zh="Claude Code 会在技能触发时执行 !`...`。逐条读完这些命令再决定信任。"),
    dict(id="SXR020", severity="HIGH", kind="builtin", check="frontmatter-hooks",
         title_en="Skill registers hooks (commands that run on agent events)",
         title_zh="技能注册了 hooks（在 Agent 事件上自动执行命令）",
         advice_en="Hooks run without per-use confirmation. Audit each hook command.",
         advice_zh="hooks 触发时不会逐次确认。逐条审计 hook 命令。"),
    dict(id="SXR022", severity="HIGH", kind="builtin", check="image-exfil",
         title_en="Markdown image/link that could carry stolen data off-site",
         title_zh="Markdown 图片/链接可能把偷到的数据带出去",
         advice_en="Renderers fetch images automatically — a URL query string is a silent outbound channel. Check what goes in it.",
         advice_zh="渲染器会自动加载图片——URL 的查询串就是一条无声的外发通道。看清楚里面塞了什么。"),
    dict(id="SXR023", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"mcpServers|\.mcp\.json|claude\s+mcp\s+add|(register|install|add)[^\n]{0,40}MCP\s+server",
         flags="i",
         title_en="Registers an MCP server (grants the agent a new tool backend)",
         title_zh="注册 MCP 服务器（等于给 Agent 接上一个新的工具后端）",
         advice_en="An MCP server is code that runs and receives your agent's data. Verify the command and its source before allowing it.",
         advice_zh="MCP 服务器是会运行、并能收到你 Agent 数据的代码。允许之前先核实它的启动命令和来源。"),
    dict(id="SXR021", severity="HIGH", kind="pattern", target="any_text",
         pattern=r"pip\s+install\s+[^\n]*(https?://|git\+)|npm\s+install\s+[^\n]*(https?://|git(\+|:))|go\s+install\s+\S+@(?!latest)|gem\s+install\s+[^\n]*--source",
         flags="i",
         title_en="Installs packages from non-registry URLs",
         title_zh="从非官方源 URL 安装依赖包",
         advice_en="URL installs bypass registry review entirely.",
         advice_zh="从 URL 直装依赖会完全绕过包仓库的审查。"),
    # ------------------------------------------------------------- MEDIUM
    dict(id="SXR030", severity="MEDIUM", kind="builtin", check="base64-blob",
         title_en="Large base64-looking blob (possible obfuscated payload)",
         title_zh="大段 base64 形态的数据块（疑似混淆载荷）",
         advice_en="Decode it and read what's inside before trusting the skill.",
         advice_zh="先解码看看里面到底是什么，再谈信任。"),
    dict(id="SXR031", severity="MEDIUM", kind="builtin", check="url-audit",
         title_en="Fetches from external domains outside the common allowlist",
         title_zh="从常见白名单以外的外部域名拉取内容",
         advice_en="Check each domain: is it the tool's official site, or somebody's VPS?",
         advice_zh="逐个核对域名：是官方站点，还是某人的 VPS？"),
    dict(id="SXR032", severity="MEDIUM", kind="builtin", check="binaries-bundled",
         title_en="Ships compiled binaries that cannot be reviewed as text",
         title_zh="附带无法以文本审查的二进制文件",
         advice_en="Prefer skills that ship readable source only.",
         advice_zh="优先选择只带可读源码的技能。"),
    dict(id="SXR033", severity="MEDIUM", kind="builtin", check="desc-mismatch",
         title_en="Description hides capabilities the skill actually uses",
         title_zh="描述未如实披露技能实际具备的能力（网络/执行）",
         advice_en="The description is what you consent to. Undisclosed network or exec is a red flag.",
         advice_zh="描述就是你的知情同意书。没写却在做网络/执行，是危险信号。"),
    dict(id="SXR034", severity="LOW", kind="builtin", check="official-shadow",
         title_en="Name matches an official Anthropic skill — confirm where yours came from",
         title_zh="与 Anthropic 官方技能重名——请确认你这份的来源",
         advice_en="Typosquatting a familiar name is the cheapest attack. The originals live in anthropics/skills.",
         advice_zh="仿冒眼熟的名字是成本最低的攻击手法。官方版本在 anthropics/skills 仓库里。"),
    dict(id="SXR035", severity="MEDIUM", kind="builtin", check="long-lines",
         title_en="Extremely long lines (common hiding spot for extra instructions)",
         title_zh="超长单行（常见的指令藏匿点，横向滚动才能看全）",
         advice_en="Wrap and read the full line — editors truncate what reviewers see.",
         advice_zh="把整行展开读完——编辑器截断的部分正是审查盲区。"),
    dict(id="SXR036", severity="MEDIUM", kind="builtin", check="frontmatter-tools",
         title_en="Pre-approves powerful tools (Bash & friends) via allowed-tools",
         title_zh="通过 allowed-tools 预批准高权限工具（如 Bash）",
         advice_en="Pre-approved Bash means commands may run without asking you first.",
         advice_zh="预批准 Bash 意味着命令可能不再逐条征求你的同意。"),
    dict(id="SXR037", severity="MEDIUM", kind="pattern", target="any_text",
         pattern=r"(printenv|env\s*>|Get-ChildItem\s+env:|process\.env|os\.environ)[^\n]{0,80}(curl|wget|http|POST|>\s*/tmp|\|\s*tee)",
         flags="i",
         title_en="Collects environment variables toward an output or the network",
         title_zh="收集环境变量并导出（环境变量里常有密钥）",
         advice_en="Env vars hold tokens and keys. Dumping them anywhere is suspect.",
         advice_zh="环境变量里躺着各种 token。任何形式的批量导出都值得怀疑。"),
    # ----------------------------------------------------------- LOW/INFO
    dict(id="SXR040", severity="LOW", kind="builtin", check="frontmatter-angle",
         title_en="Angle brackets in frontmatter (spec advises against, injection-prone)",
         title_zh="frontmatter 含尖括号（规范不建议，易被注入利用）",
         advice_en="Keep frontmatter plain text per the Agent Skills spec.",
         advice_zh="按 Agent Skills 规范，frontmatter 保持纯文本。"),
    dict(id="SXR041", severity="LOW", kind="builtin", check="size-audit",
         title_en="Oversized SKILL.md (spec recommends under 500 lines)",
         title_zh="SKILL.md 过长（规范建议 500 行以内）",
         advice_en="Long skills are hard to review — and hide things well.",
         advice_zh="越长越难审查，也越容易藏东西。"),
    dict(id="SXR042", severity="LOW", kind="builtin", check="spec-format",
         title_en="name/directory mismatch or invalid skill name",
         title_zh="name 与目录不一致，或技能名不符合规范",
         advice_en="Not a security issue by itself, but sloppy metadata correlates with sloppy skills.",
         advice_zh="本身不是安全问题，但元数据潦草的技能通常整体潦草。"),
    dict(id="SXR050", severity="INFO", kind="builtin", check="scripts-present",
         title_en="Ships executable scripts (inventory)",
         title_zh="附带可执行脚本（清单）",
         advice_en="Scripts are normal for skills — this is your reading list, not an alarm.",
         advice_zh="技能带脚本很正常——这是给你的阅读清单，不是警报。"),
]

RULES_BY_ID = {r["id"]: r for r in RULES}


# ---------------------------------------------------------------------------
# Small utilities (shared style with battle-tested siblings)
# ---------------------------------------------------------------------------

def _harden_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


class Palette(object):
    def __init__(self, enabled):
        self.enabled = enabled

    def _c(self, code, s):
        if not self.enabled:
            return s
        return "\x1b[%sm%s\x1b[0m" % (code, s)

    def bold(self, s):    return self._c("1", s)
    def dim(self, s):     return self._c("2", s)
    def red(self, s):     return self._c("31", s)
    def green(self, s):   return self._c("32", s)
    def yellow(self, s):  return self._c("33", s)
    def blue(self, s):    return self._c("34", s)
    def magenta(self, s): return self._c("35", s)
    def cyan(self, s):    return self._c("36", s)

    def sev(self, sev, s):
        return {"CRITICAL": self.red, "HIGH": self.magenta,
                "MEDIUM": self.yellow, "LOW": self.cyan,
                "INFO": self.dim}.get(sev, self.dim)(s)


def make_palette(force_off=False):
    if force_off or os.environ.get("NO_COLOR") is not None:
        return Palette(False)
    if not sys.stdout.isatty():
        return Palette(False)
    if os.name == "nt":
        os.system("")
    return Palette(True)


def pick_lang(requested):
    if requested in ("en", "zh", "both"):
        return requested
    loc = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    if "zh" in loc:
        return "zh"
    if os.name == "nt":
        try:
            import ctypes
            if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x04:
                return "zh"
        except Exception:
            pass
    return "en"


def read_text(path):
    try:
        with io.open(path, "rb") as f:
            raw = f.read(MAX_TEXT_BYTES)
    except (IOError, OSError):
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def parse_frontmatter(text):
    """Return (frontmatter_text, body_text, fields_dict)."""
    m = re.match(r"﻿?\s*---\s*\n(.*?)\n---\s*\n?(.*)", text, re.DOTALL)
    if not m:
        return "", text, {}
    front, body = m.group(1), m.group(2)
    fields = {}
    key = None
    for line in front.splitlines():
        stripped = line.strip()
        kv = re.match(r"([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)", stripped)
        if kv and not stripped.startswith("- "):
            key = kv.group(1).lower()
            fields[key] = kv.group(2).strip()
        elif key is not None and stripped:
            fields[key] = (fields.get(key, "") + " " + stripped).strip()
    return front, body, fields


# ---------------------------------------------------------------------------
# Skill model: everything the rules need to look at
# ---------------------------------------------------------------------------

class SkillUnderScan(object):
    def __init__(self, path, source=None):
        self.path = path
        self.source = source       # "owner/repo" when fetched from GitHub
        self.name = os.path.basename(os.path.abspath(path))
        self.files = []            # relative paths
        self.skill_md = ""
        self.frontmatter = ""
        self.body = ""
        self.fields = {}
        self.script_texts = {}     # rel -> text
        self.other_texts = {}      # rel -> text  (references, assets)
        self.ignored = {}          # rel -> set(rule ids) from ignore comments
        self._collect()

    def _collect(self):
        for dirpath, dirnames, filenames in os.walk(self.path):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__", "node_modules")]
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.path).replace(os.sep, "/")
                self.files.append(rel)
        md = os.path.join(self.path, "SKILL.md")
        if os.path.isfile(md):
            self.skill_md = read_text(md)
            self.frontmatter, self.body, self.fields = parse_frontmatter(self.skill_md)
        for rel in self.files:
            if BOILERPLATE_RE.search(rel):
                continue
            low = rel.lower()
            full = os.path.join(self.path, rel)
            if low.endswith(SCRIPT_EXT):
                self.script_texts[rel] = read_text(full)
            elif low.endswith((".md", ".txt", ".json", ".yaml", ".yml")) and rel != "SKILL.md":
                self.other_texts[rel] = read_text(full)
        for rel, text in list(self.script_texts.items()) + \
                list(self.other_texts.items()) + [("SKILL.md", self.skill_md)]:
            for m in IGNORE_RE.finditer(text or ""):
                ids = {x.strip().upper() for x in m.group(1).split(",")}
                self.ignored.setdefault(rel, set()).update(ids)

    def is_reference(self, where):
        """True for on-demand material rather than auto-loaded/executed code."""
        return where not in ("SKILL.md", "SKILL.md (frontmatter)") and \
            where not in self.script_texts

    def target_text(self, target):
        """Yield (label, text) pairs for a rule target."""
        if target == "skill_md":
            yield "SKILL.md", self.skill_md
        elif target == "frontmatter":
            yield "SKILL.md (frontmatter)", self.frontmatter
        elif target == "body":
            yield "SKILL.md", self.body
        elif target == "scripts":
            for rel, text in self.script_texts.items():
                yield rel, text
        elif target == "any_text":
            yield "SKILL.md", self.skill_md
            for rel, text in self.script_texts.items():
                yield rel, text
            for rel, text in self.other_texts.items():
                yield rel, text


def looks_like_skill(path):
    return os.path.isfile(os.path.join(path, "SKILL.md"))


SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".next", "target", "site-packages"}


def discover_skills(root, max_depth=5):
    """Every skill directory at or under root.

    Walks a bounded depth so `scan owner/repo` finds skills wherever a repo
    chose to put them (skills/, document-skills/, plugins/x/skills/, ...),
    without descending into vendored trees. A skill never nests inside
    another skill, so matched directories are not traversed further.
    """
    if looks_like_skill(root):
        return [root]
    if not os.path.isdir(root):
        return []
    out = []
    root_depth = os.path.abspath(root).rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, _ in os.walk(root):
        depth = os.path.abspath(dirpath).rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not d.startswith(".")
                             or d in (".claude", ".agents", ".cursor", ".github"))
        keep = []
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if looks_like_skill(p):
                out.append(p)          # don't descend into a skill
            else:
                keep.append(d)
        dirnames[:] = keep
    return sorted(out)


def default_roots():
    roots = [os.path.expanduser(r) for r in USER_ROOTS]
    roots += [os.path.abspath(r) for r in PROJECT_ROOTS]
    return [r for r in roots if os.path.isdir(r)]


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

def line_of(text, index):
    return text.count("\n", 0, index) + 1


def excerpt_at(text, index, width=80):
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    line = text[start:end].strip()
    if len(line) > width:
        line = line[:width] + "…"
    return line


def finding(rule, where, line, excerpt, severity=None, note=""):
    return {
        "rule": rule["id"], "severity": severity or rule["severity"],
        "title_en": rule["title_en"], "title_zh": rule["title_zh"],
        "advice_en": rule["advice_en"], "advice_zh": rule["advice_zh"],
        "file": where, "line": line, "excerpt": excerpt, "note": note,
    }


def run_pattern_rule(rule, skill):
    out = []
    try:
        rx = re.compile(rule["pattern"],
                        re.IGNORECASE if "i" in rule.get("flags", "") else 0)
    except re.error:
        return out
    for where, text in skill.target_text(rule["target"]):
        if not text or rule["id"] in skill.ignored.get(where, ()):
            continue
        sev = (demote(rule["severity"]) if skill.is_reference(where)
               else rule["severity"])
        seen_lines = set()
        for m in rx.finditer(text):
            if not m.group(0).strip():
                continue
            ln = line_of(text, m.start())
            if ln in seen_lines:
                continue
            seen_lines.add(ln)
            this_sev, note = sev, ""
            if is_mention(text, m.start(), m.end()):
                this_sev, note = demote(sev, 2), "quoted/discussed, not issued"
            out.append(finding(rule, where, ln, excerpt_at(text, m.start()),
                               this_sev, note))
            if len(seen_lines) >= 3:      # cap noise per file per rule
                break
    return out


ZERO_WIDTH = "​‌‍⁠﻿"
BIDI = "‪‫‬‭‮⁦⁧⁨⁩"


def run_builtin_rule(rule, skill, all_findings):
    check = rule["check"]
    out = []

    if check == "unicode-hidden":
        for where, text in skill.target_text("any_text"):
            bad = [(i, ch) for i, ch in enumerate(text)
                   if ch in ZERO_WIDTH or ch in BIDI]
            if bad:
                i, ch = bad[0]
                out.append(finding(rule, where, line_of(text, i),
                                   "%d invisible char(s), first U+%04X"
                                   % (len(bad), ord(ch))))

    elif check == "exfil-combo":
        ids = {f["rule"] for f in all_findings}
        if "SXR011" in ids and "SXR012" in ids:
            out.append(finding(rule, "(skill-wide)", 0,
                               "credential paths + network upload both present"))

    elif check == "hidden-html-comments":
        for where, text in (("SKILL.md", skill.skill_md),):
            for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
                inner = m.group(1).strip()
                if len(inner) > 60 and re.search(
                        r"\b(you|must|always|never|do|run|execute|send|write)\b",
                        inner, re.IGNORECASE):
                    out.append(finding(rule, where, line_of(text, m.start()),
                                       inner[:80] + "…"))

    elif check == "frontmatter-hooks":
        if "hooks" in skill.fields:
            out.append(finding(rule, "SKILL.md (frontmatter)", 1,
                               "hooks: %s" % skill.fields["hooks"][:70]))

    elif check == "base64-blob":
        for where, text in skill.target_text("any_text"):
            m = re.search(r"[A-Za-z0-9+/]{200,}={0,2}", text)
            if m:
                out.append(finding(rule, where, line_of(text, m.start()),
                                   "%d-char blob" % len(m.group(0))))

    elif check == "url-audit":
        # Only URLs that something actually FETCHES matter. A URL merely
        # cited in prose is documentation, not behaviour.
        fetchy = re.compile(
            r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|fetch\(|"
            r"requests\.\w+\(|urlopen\(|axios\.\w+\(|http\.get|src\s*=|href\s*=)"
            r"[^\n]{0,120}?https?://([A-Za-z0-9.-]+)", re.IGNORECASE)
        domains = {}
        for where, text in skill.target_text("any_text"):
            if rule["id"] in skill.ignored.get(where, ()):
                continue
            for m in fetchy.finditer(text):
                d = m.group(2).lower().rstrip(".")
                if any(d == a or d.endswith("." + a) for a in URL_ALLOWLIST):
                    continue
                sev = (demote(rule["severity"]) if skill.is_reference(where)
                       else rule["severity"])
                domains.setdefault(d, (where, line_of(text, m.start()), sev))
        for d, (where, ln, sev) in sorted(domains.items())[:5]:
            out.append(finding(rule, where, ln, d, sev))

    elif check == "image-exfil":
        # A markdown image is fetched by the renderer with no click and no
        # confirmation. If its URL carries a query string, that query string
        # is an outbound channel. Badge/shield services do this legitimately,
        # so they are excluded; everything else is worth a human look.
        badge_hosts = ("shields.io", "img.shields.io", "badgen.net",
                       "badge.fury.io", "codecov.io", "circleci.com",
                       "travis-ci.org", "travis-ci.com", "appveyor.com",
                       "coveralls.io", "snyk.io", "githubusercontent.com",
                       "github.com", "gitlab.com")
        img = re.compile(r"!\[[^\]]*\]\(\s*(https?://([A-Za-z0-9.-]+)[^)\s]*)")
        for where, text in skill.target_text("any_text"):
            if rule["id"] in skill.ignored.get(where, ()):
                continue
            for m in img.finditer(text):
                url, host = m.group(1), m.group(2).lower()
                if "?" not in url:
                    continue
                if any(host == b or host.endswith("." + b) for b in badge_hosts):
                    continue
                sev = (demote(rule["severity"]) if skill.is_reference(where)
                       else rule["severity"])
                out.append(finding(rule, where, line_of(text, m.start()),
                                   url[:90], sev))
                break

    elif check == "binaries-bundled":
        bins = [f for f in skill.files if f.lower().endswith(BINARY_EXT)]
        if bins:
            out.append(finding(rule, bins[0], 0,
                               ", ".join(bins[:4]) + ("…" if len(bins) > 4 else "")))

    elif check == "desc-mismatch":
        # Only worth flagging when the skill *sends* data outward yet the
        # description — the thing the user consents to — is silent about it.
        # Referencing a font/CDN URL while building a local file is not that.
        desc = skill.fields.get("description", "").lower()
        discloses = bool(re.search(
            r"network|internet|online|upload|send|post|fetch|download|"
            r"api|request|url|web|http|server|cloud|remote|sync", desc))
        uploads = re.compile(
            r"(curl|wget)\s[^\n]*\s(-d|--data|--upload-file|-T|-F)\b|"
            r"requests\.(post|put|patch)\(|\.upload\(|"
            r"urlopen\([^\n]*data=|fetch\([^\n]*method:\s*['\"]POST", re.IGNORECASE)
        sends = any(uploads.search(t) for _, t in skill.target_text("scripts")) \
            or bool(uploads.search(skill.body))
        if sends and not discloses and desc:
            out.append(finding(rule, "SKILL.md", 1,
                               "uploads data but description doesn't mention it"))

    elif check == "official-shadow":
        if skill.name in OFFICIAL_SKILL_NAMES and \
                (skill.source or "").lower() not in OFFICIAL_SOURCES:
            out.append(finding(rule, "(directory name)", 0, skill.name))

    elif check == "long-lines":
        for where, text in (("SKILL.md", skill.skill_md),):
            for i, ln_text in enumerate(text.splitlines(), 1):
                if len(ln_text) > 1500:
                    out.append(finding(rule, where, i,
                                       "%d chars on one line" % len(ln_text)))
                    break

    elif check == "frontmatter-tools":
        tools = skill.fields.get("allowed-tools", "")
        if re.search(r"\bBash\b|\bShell\b|\bWrite\b", tools):
            out.append(finding(rule, "SKILL.md (frontmatter)", 1,
                               "allowed-tools: %s" % tools[:70]))

    elif check == "frontmatter-angle":
        if "<" in skill.frontmatter or ">" in skill.frontmatter:
            out.append(finding(rule, "SKILL.md (frontmatter)", 1,
                               "angle bracket in frontmatter"))

    elif check == "size-audit":
        n = skill.skill_md.count("\n") + 1 if skill.skill_md else 0
        if n > 500:
            out.append(finding(rule, "SKILL.md", n, "%d lines" % n))

    elif check == "spec-format":
        name = skill.fields.get("name", "")
        if name and name != skill.name:
            out.append(finding(rule, "SKILL.md (frontmatter)", 1,
                               "name %r vs directory %r" % (name, skill.name)))
        elif name and not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", name):
            out.append(finding(rule, "SKILL.md (frontmatter)", 1,
                               "invalid name %r" % name))

    elif check == "scripts-present":
        if skill.script_texts:
            names = sorted(skill.script_texts)
            out.append(finding(rule, names[0], 0,
                               "%d script(s): %s" % (len(names),
                                ", ".join(names[:4]) +
                                ("…" if len(names) > 4 else ""))))
    return out


def score_findings(findings):
    """Grade the skill.

    Deductions are charged per RULE, not per hit: five mentions of one
    suspicious pattern say roughly what one mention says, and charging each
    of them buried real CRITICALs under a pile of MEDIUM noise in testing.
    """
    charged = {}
    for f in findings:
        key = f["rule"]
        worst = charged.get(key)
        if worst is None or SEVERITIES.index(f["severity"]) < SEVERITIES.index(worst):
            charged[key] = f["severity"]
    score = 100
    for sev in charged.values():
        score -= SEV_SCORE[sev]
    return max(0, score)


def scan_skill(path, source=None):
    """Return (skill, findings, score, grade)."""
    skill = SkillUnderScan(path, source=source)
    findings = []
    for rule in RULES:
        if rule["kind"] == "pattern":
            findings.extend(run_pattern_rule(rule, skill))
    for rule in RULES:
        if rule["kind"] == "builtin":
            findings.extend(run_builtin_rule(rule, skill, findings))
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["rule"]))
    score = score_findings(findings)
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    if not skill.skill_md:
        grade, score = "?", 0
    return skill, findings, score, grade


# ---------------------------------------------------------------------------
# Remote scanning: GitHub zipball, stdlib only
# ---------------------------------------------------------------------------

def fetch_github(spec, workdir):
    """spec = owner/repo[/sub/path]. Download zipball, return local dir."""
    parts = spec.split("/")
    if len(parts) < 2:
        raise ValueError("expected owner/repo[/path]")
    owner, repo = parts[0], parts[1]
    sub = "/".join(parts[2:])
    import urllib.request
    import urllib.error

    def get(url):
        req = urllib.request.Request(url, headers={
            "User-Agent": "skillxray/%s" % __version__,
            "Accept": "application/vnd.github+json"})
        return urllib.request.urlopen(req, timeout=30)

    # codeload's /zip/HEAD needs no API call, so this keeps working when the
    # unauthenticated API is rate-limited. The named branches are fallbacks
    # for the rare repo where HEAD isn't served.
    zpath = os.path.join(workdir, "repo.zip")
    last_error = None
    for ref in ("HEAD", "refs/heads/main", "refs/heads/master"):
        url = "https://codeload.github.com/%s/%s/zip/%s" % (owner, repo, ref)
        try:
            with get(url) as r, open(zpath, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
            break
        except urllib.error.HTTPError as e:
            last_error = e
            continue
    else:
        raise RuntimeError("could not download %s/%s (%s)"
                           % (owner, repo, last_error))
    extract = os.path.join(workdir, "x")
    with zipfile.ZipFile(zpath) as z:
        base = z.namelist()[0].split("/")[0]
        for member in z.namelist():
            target = os.path.normpath(os.path.join(extract, member))
            if not target.startswith(os.path.normpath(extract)):
                continue  # zip-slip guard
            if member.endswith("/"):
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())
    root = os.path.join(extract, base)
    return os.path.join(root, sub.replace("/", os.sep)) if sub else root


# ---------------------------------------------------------------------------
# Lockfile: sha256 of every file of every installed skill
# ---------------------------------------------------------------------------

LOCKFILE = "skillxray.lock"


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(roots):
    snap = {"version": 1, "tool": "skillxray %s" % __version__, "skills": {}}
    for root in roots:
        for sdir in discover_skills(root):
            key = os.path.abspath(sdir)
            files = {}
            for dirpath, dirnames, filenames in os.walk(sdir):
                dirnames[:] = [d for d in dirnames if d != ".git"]
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, sdir).replace(os.sep, "/")
                    try:
                        files[rel] = hash_file(full)
                    except (IOError, OSError):
                        files[rel] = "(unreadable)"
            snap["skills"][key] = files
    return snap


def lock_path():
    return os.path.join(os.path.expanduser("~"), ".skillxray", LOCKFILE)


def cmd_lock(roots, pal, as_json):
    snap = snapshot(roots)
    path = lock_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(snap, f, indent=1, sort_keys=True)
    n = len(snap["skills"])
    total = sum(len(v) for v in snap["skills"].values())
    if as_json:
        print(json.dumps({"locked": n, "files": total, "path": path}))
    else:
        print(pal.green("locked %d skill(s), %d file(s) → %s" % (n, total, path)))
        print(pal.dim("run `skillxray verify` any time to detect tampering"))
    return 0


def cmd_verify(roots, pal, as_json, lang):
    path = lock_path()
    if not os.path.isfile(path):
        print("no lockfile yet — run `skillxray lock` first")
        return 2
    with io.open(path, "r", encoding="utf-8") as f:
        old = json.load(f)
    new = snapshot(roots)
    drift = []
    for skill, files in sorted(old["skills"].items()):
        now = new["skills"].get(skill)
        if now is None:
            drift.append((skill, "removed", ""))
            continue
        for rel, digest in sorted(files.items()):
            if rel not in now:
                drift.append((skill, "file deleted", rel))
            elif now[rel] != digest:
                drift.append((skill, "file CHANGED", rel))
        for rel in sorted(set(now) - set(files)):
            drift.append((skill, "file added", rel))
    for skill in sorted(set(new["skills"]) - set(old["skills"])):
        drift.append((skill, "new skill (unlocked)", ""))
    if as_json:
        print(json.dumps({"drift": [
            {"skill": s, "kind": k, "file": f} for s, k, f in drift]},
            ensure_ascii=False, indent=2))
        return 1 if drift else 0
    if not drift:
        print(pal.green("verify: all skills match the lockfile — no drift"
                        if lang != "zh" else "verify: 与锁文件完全一致——没有漂移"))
        return 0
    for skill, kind, f in drift:
        mark = pal.red("!") if "CHANGED" in kind else pal.yellow("~")
        print("%s %s  %s  %s" % (mark, pal.bold(os.path.basename(skill)),
                                 kind, f))
    print("")
    print(pal.red("%d change(s) since lock." % len(drift)) + " " +
          (pal.dim("Review them, then re-run `skillxray lock` to accept.")
           if lang != "zh" else
           pal.dim("逐条审查后，用 `skillxray lock` 重新锁定以接受变更。")))
    return 1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def grade_color(pal, grade):
    return {"A": pal.green, "B": pal.green, "C": pal.yellow,
            "D": pal.magenta, "F": pal.red, "?": pal.dim}[grade]


def render_report(results, pal, lang, verbose):
    lines = []
    worst = "A"
    order = "ABCDF?"
    for skill, findings, score, grade in results:
        if order.index(grade if grade in order else "?") > order.index(worst):
            worst = grade
        gc = grade_color(pal, grade)
        lines.append("%s %s  %s" % (
            gc("[%s]" % grade),
            pal.bold(skill.name.ljust(28)),
            pal.dim("%3d/100  %s" % (score, skill.path))))
        if grade == "?":
            lines.append(pal.dim("     no SKILL.md found — not a skill directory?"))
        shown = findings if verbose else [
            f for f in findings if f["severity"] != "INFO"]
        for f in shown:
            title = f["title_zh"] if lang == "zh" else f["title_en"]
            if f.get("note"):
                title += pal.dim("  (%s)" % f["note"])
            loc = f["file"] + (":%d" % f["line"] if f["line"] else "")
            lines.append("     %s %s" % (
                pal.sev(f["severity"], "%-8s" % f["severity"]), title))
            lines.append(pal.dim("              %s  %s" % (loc, f["excerpt"])))
            advice = f["advice_zh"] if lang == "zh" else f["advice_en"]
            lines.append(pal.dim("              ↳ " + advice))
    return "\n".join(lines), worst


def summarize(results, pal, lang):
    total = len(results)
    counts = dict((s, 0) for s in SEVERITIES)
    for _, findings, _, _ in results:
        for f in findings:
            counts[f["severity"]] += 1
    bits = ["%s %s" % (pal.sev(s, s.lower()), counts[s])
            for s in SEVERITIES if counts[s]]
    if lang == "zh":
        head = "已安检 %d 个技能" % total
    else:
        head = "x-rayed %d skill(s)" % total
    return head + ("  ·  " + "  ".join(bits) if bits else
                   "  ·  " + pal.green("all clear" if lang != "zh" else "全部干净"))


def cmd_scan(args, pal, lang, as_json, fail_on, verbose, fmt="text", out=None):
    targets = []
    tmp = None
    source = None
    if not args:
        roots = default_roots()
        if not roots:
            print("no skill directories found on this machine"
                  if lang != "zh" else "本机没有发现任何技能目录")
            return 0
        for r in roots:
            targets.extend(discover_skills(r))
    else:
        spec = args[0]
        if os.path.exists(spec):
            targets = discover_skills(spec)
            if not targets:
                print("no SKILL.md under %s" % spec)
                return 2
        elif re.match(r"^[\w.-]+/[\w.-]+(/.*)?$", spec):
            source = "/".join(spec.split("/")[:2])
            tmp = tempfile.mkdtemp(prefix="skillxray-")
            print(pal.dim(("fetching %s …" if lang != "zh"
                           else "正在拉取 %s …") % spec))
            try:
                local = fetch_github(spec, tmp)
            except Exception as e:
                print(pal.red("fetch failed: %s" % e))
                return 2
            targets = discover_skills(local)
            if not targets:
                print("no SKILL.md found in %s" % spec)
                return 2
        else:
            print("not a path or owner/repo: %s" % spec)
            return 2

    results = [scan_skill(t, source=source) for t in targets]

    if as_json:
        fmt = "json"
    rendered = None
    if fmt == "json":
        payload = []
        for skill, findings, score, grade in results:
            payload.append({"name": skill.name, "path": skill.path,
                            "score": score, "grade": grade,
                            "findings": findings})
        rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    elif fmt == "sarif":
        rendered = json.dumps(sarif_report(results), ensure_ascii=False, indent=2)
    elif fmt == "markdown":
        rendered = markdown_report(results, lang)

    if rendered is not None:
        if out:
            with io.open(out, "w", encoding="utf-8", newline="\n") as f:
                f.write(rendered + "\n")
            print(pal.dim("wrote %s report to %s" % (fmt, out)))
        else:
            print(rendered)
    else:
        report, _ = render_report(results, pal, lang, verbose)
        print(report)
        print("")
        print(summarize(results, pal, lang))
        if out:
            with io.open(out, "w", encoding="utf-8", newline="\n") as f:
                f.write(markdown_report(results, lang) + "\n")
    threshold = SEVERITIES.index(fail_on)
    for _, findings, _, _ in results:
        for f in findings:
            if SEVERITIES.index(f["severity"]) <= threshold:
                return 1
    return 0


def sarif_report(results):
    """SARIF 2.1.0 — GitHub Code Scanning ingests this and shows findings
    inline on PRs and in the repository's Security tab."""
    sev_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
               "LOW": "note", "INFO": "note"}
    # GitHub ranks by security-severity (CVSS-like) when present.
    score_map = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0",
                 "LOW": "3.0", "INFO": "0.0"}
    rules = []
    for r in RULES:
        rules.append({
            "id": r["id"],
            "name": r["id"],
            "shortDescription": {"text": r["title_en"]},
            "fullDescription": {"text": "%s  /  %s" % (r["title_en"], r["title_zh"])},
            "help": {
                "text": "%s\n\n%s" % (r["advice_en"], r["advice_zh"]),
                "markdown": "**%s**\n\n%s\n\n%s" % (r["title_en"], r["advice_en"],
                                                    r["advice_zh"]),
            },
            "defaultConfiguration": {"level": sev_map[r["severity"]]},
            "properties": {
                "tags": ["security", "agent-skills", r["severity"].lower()],
                "security-severity": score_map[r["severity"]],
            },
        })
    seen_rules = set()
    sarif_results = []
    for skill, findings, _score, _grade in results:
        for f in findings:
            if f["severity"] == "INFO":
                continue
            seen_rules.add(f["rule"])
            # Findings that describe the skill as a whole, or its frontmatter,
            # carry a human label rather than a path. Code scanning needs a
            # real file, so anchor those on SKILL.md.
            where = f["file"]
            if where.startswith("(") or " (" in where:
                where = where.split(" (")[0] if " (" in where else "SKILL.md"
            rel = os.path.join(skill.path, where).replace(os.sep, "/")
            rel = re.sub(r"^\./", "", rel)
            msg = f["title_en"]
            if f.get("note"):
                msg += " (%s)" % f["note"]
            if f.get("excerpt"):
                msg += "\n> %s" % f["excerpt"]
            sarif_results.append({
                "ruleId": f["rule"],
                "level": sev_map[f["severity"]],
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel},
                        "region": {"startLine": max(1, f["line"] or 1)},
                    }
                }],
                "properties": {"skill": skill.name, "severity": f["severity"]},
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "skillxray",
                "version": __version__,
                "informationUri": "https://github.com/aixintan90/skillxray",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }


def markdown_report(results, lang="en"):
    """A GitHub-flavoured summary, for Action job summaries and PR comments."""
    lines = []
    total = len(results)
    counts = dict((s, 0) for s in SEVERITIES)
    for _s, findings, _sc, _g in results:
        for f in findings:
            counts[f["severity"]] += 1
    worst = next((s for s in SEVERITIES if counts[s]), None)
    icon = {"CRITICAL": "🛑", "HIGH": "🚨", "MEDIUM": "⚠️",
            "LOW": "🔵", "INFO": "ℹ️"}
    headline = ("🛑 skillxray found critical issues" if counts["CRITICAL"] else
                "🚨 skillxray found high-severity issues" if counts["HIGH"] else
                "⚠️ skillxray found issues to review" if counts["MEDIUM"] else
                "✅ skillxray found nothing above LOW")
    lines.append("## %s" % headline)
    lines.append("")
    tally = ", ".join("**%d** %s" % (counts[s], s.lower())
                      for s in SEVERITIES if counts[s]) or "**0** findings"
    lines.append("x-rayed **%d** skill(s) — %s" % (total, tally))
    lines.append("")
    lines.append("| Skill | Grade | Score | Findings |")
    lines.append("|---|:--:|--:|---|")
    for skill, findings, score, grade in sorted(
            results, key=lambda r: r[2]):
        top = [f for f in findings if f["severity"] != "INFO"]
        summary = ", ".join("%s %s" % (icon[f["severity"]], f["rule"])
                            for f in top[:3]) or "—"
        if len(top) > 3:
            summary += " +%d more" % (len(top) - 3)
        lines.append("| `%s` | **%s** | %d | %s |" % (skill.name, grade, score, summary))
    detailed = [(s, f) for s, findings, _sc, _g in results for f in findings
                if f["severity"] in ("CRITICAL", "HIGH")]
    if detailed:
        lines.append("")
        lines.append("<details><summary><b>Critical &amp; high findings</b></summary>")
        lines.append("")
        for skill, f in detailed:
            loc = "%s%s" % (f["file"], ":%d" % f["line"] if f["line"] else "")
            lines.append("- **%s** `%s` — %s" % (f["severity"], skill.name, f["title_en"]))
            lines.append("  - `%s` — %s" % (loc, f["excerpt"]))
            lines.append("  - ↳ %s" % f["advice_en"])
        lines.append("")
        lines.append("</details>")
    lines.append("")
    lines.append("<sub>Scanned by [skillxray](https://github.com/aixintan90/skillxray) "
                 "v%s — a security scanner for AI agent skills. "
                 "Findings are for human review, not a guarantee of safety.</sub>" % __version__)
    return "\n".join(lines)


def cmd_rules(pal, as_json):
    if as_json:
        print(json.dumps(RULES, ensure_ascii=False, indent=2))
        return 0
    for r in RULES:
        print("%s %s  %s" % (pal.sev(r["severity"], "%-8s" % r["severity"]),
                             pal.cyan(r["id"]), r["title_en"]))
        print(pal.dim("          " + r["title_zh"]))
    print(pal.dim("\n%d rules. Add yours: CONTRIBUTING.md" % len(RULES)))
    return 0


def print_usage(pal):
    print(pal.bold("skillxray") + " v%s — X-ray your agent's skills before you trust them." % __version__)
    print("           技能安检机 · offline · zero dependencies")
    print("")
    print(pal.bold("usage:"))
    print("  skillxray scan                    scan every skill installed on this machine")
    print("  skillxray scan <path>             scan one skill or a folder of skills")
    print("  skillxray scan owner/repo[/path]  scan a GitHub skill BEFORE installing it")
    print("  skillxray lock                    fingerprint installed skills (sha256)")
    print("  skillxray verify                  detect any file changed since lock")
    print("  skillxray rules                   list all detection rules")
    print("")
    print(pal.bold("options:"))
    print("  --lang en|zh|both    report language (default: auto)")
    print("  --format FMT         text (default), json, sarif, markdown")
    print("  --out FILE           write the report to a file instead of stdout")
    print("  --json               shorthand for --format json")
    print("  --fail-on SEV        exit 1 at/above this severity (default: high)")
    print("  --verbose            include INFO-level findings")
    print("  --no-color           plain output")
    print("  --version            print version")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    _harden_stdio()

    lang = "auto"
    no_color = False
    as_json = False
    verbose = False
    fail_on = "HIGH"
    fmt = "text"
    out = None
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            rest.extend(argv[i + 1:])
            break
        if a == "--format" and i + 1 < len(argv):
            fmt = argv[i + 1].lower(); i += 2; continue
        if a.startswith("--format="):
            fmt = a.split("=", 1)[1].lower(); i += 1; continue
        if a == "--out" and i + 1 < len(argv):
            out = argv[i + 1]; i += 2; continue
        if a.startswith("--out="):
            out = a.split("=", 1)[1]; i += 1; continue
        if a == "--lang" and i + 1 < len(argv):
            lang = argv[i + 1].lower(); i += 2; continue
        if a.startswith("--lang="):
            lang = a.split("=", 1)[1].lower(); i += 1; continue
        if a == "--fail-on" and i + 1 < len(argv):
            fail_on = argv[i + 1].upper(); i += 2; continue
        if a.startswith("--fail-on="):
            fail_on = a.split("=", 1)[1].upper(); i += 1; continue
        if a == "--no-color":
            no_color = True; i += 1; continue
        if a == "--json":
            as_json = True; i += 1; continue
        if a == "--verbose":
            verbose = True; i += 1; continue
        if a in ("--version", "-V"):
            print("skillxray %s" % __version__)
            return 0
        if a in ("--help", "-h"):
            print_usage(make_palette(no_color))
            return 0
        rest.append(a); i += 1
    argv = rest

    if lang not in ("auto", "en", "zh", "both"):
        print("skillxray: unknown --lang %r (use en, zh or both)" % lang)
        return 2
    if fail_on not in SEVERITIES:
        print("skillxray: unknown --fail-on %r (use %s)" %
              (fail_on, "/".join(s.lower() for s in SEVERITIES)))
        return 2
    if fmt not in ("text", "json", "sarif", "markdown"):
        print("skillxray: unknown --format %r (use text, json, sarif or markdown)"
              % fmt)
        return 2

    pal = make_palette(no_color)
    lang = pick_lang(lang)

    if not argv:
        print_usage(pal)
        return 2
    cmd = argv[0]
    if cmd == "scan":
        return cmd_scan(argv[1:], pal, lang, as_json, fail_on, verbose, fmt, out)
    if cmd == "lock":
        return cmd_lock(default_roots(), pal, as_json)
    if cmd == "verify":
        return cmd_verify(default_roots(), pal, as_json, lang)
    if cmd == "rules":
        return cmd_rules(pal, as_json)
    print("skillxray: unknown command %r" % cmd)
    print_usage(pal)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except OSError as exc:
        import errno
        if exc.errno in (errno.EPIPE, errno.EINVAL):
            try:
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
            except Exception:
                pass
            sys.exit(0)
        raise
