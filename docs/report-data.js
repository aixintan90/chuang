// GENERATED from the survey run — see build_web.py / the report script.
window.SKILLXRAY_REPORT = {
 "generated": "2026-07-26",
 "tool_version": "0.1.0",
 "rules": 42,
 "repos_attempted": 596,
 "repos_with_skills": 577,
 "repos_failed": 13,
 "skills": 45702,
 "grades": {
  "A": 41301,
  "B": 2393,
  "C": 1352,
  "D": 404,
  "F": 252
 },
 "severity": {
  "CRITICAL": 714,
  "HIGH": 5626,
  "MEDIUM": 19442,
  "LOW": 22374,
  "INFO": 6831
 },
 "with_critical": 425,
 "with_crit_high": 2994,
 "clean": 21964,
 "hard_signals": {
  "SXR003": 65,
  "SXR002": 93,
  "SXR004": 39,
  "SXR006": 1,
  "SXR009": 56,
  "SXR008": 31,
  "SXR018": 83,
  "SXR022": 32
 },
 "hard_any": 353,
 "hard_any_repos": 108,
 "top_rules": [
  {
   "id": "SXR040",
   "hits": 11648,
   "skills": 7826,
   "severity": "LOW",
   "title_en": "Angle brackets in frontmatter (spec advises against, injection-prone)",
   "title_zh": "frontmatter 含尖括号（规范不建议，易被注入利用）"
  },
  {
   "id": "SXR036",
   "hits": 9191,
   "skills": 6642,
   "severity": "MEDIUM",
   "title_en": "Pre-approves powerful tools (Bash & friends) via allowed-tools",
   "title_zh": "通过 allowed-tools 预批准高权限工具（如 Bash）"
  },
  {
   "id": "SXR050",
   "hits": 6421,
   "skills": 5951,
   "severity": "INFO",
   "title_en": "Ships executable scripts (inventory)",
   "title_zh": "附带可执行脚本（清单）"
  },
  {
   "id": "SXR031",
   "hits": 4764,
   "skills": 2717,
   "severity": "MEDIUM",
   "title_en": "Fetches from external domains outside the common allowlist",
   "title_zh": "从常见白名单以外的外部域名拉取内容"
  },
  {
   "id": "SXR042",
   "hits": 3929,
   "skills": 3866,
   "severity": "LOW",
   "title_en": "name/directory mismatch or invalid skill name",
   "title_zh": "name 与目录不一致，或技能名不符合规范"
  },
  {
   "id": "SXR041",
   "hits": 3617,
   "skills": 2589,
   "severity": "LOW",
   "title_en": "Oversized SKILL.md (spec recommends under 500 lines)",
   "title_zh": "SKILL.md 过长（规范建议 500 行以内）"
  },
  {
   "id": "SXR012",
   "hits": 2829,
   "skills": 1097,
   "severity": "HIGH",
   "title_en": "Uploads data to the network",
   "title_zh": "存在向网络上传数据的行为"
  },
  {
   "id": "SXR011",
   "hits": 1723,
   "skills": 504,
   "severity": "HIGH",
   "title_en": "References credential / secret file paths",
   "title_zh": "引用了凭据或密钥文件路径（~/.ssh、.aws/credentials 等）"
  },
  {
   "id": "SXR026",
   "hits": 1382,
   "skills": 351,
   "severity": "MEDIUM",
   "title_en": "Modifies the agent's persistent memory / instruction files",
   "title_zh": "修改 Agent 的长期记忆 / 指令文件"
  },
  {
   "id": "SXR013",
   "hits": 1376,
   "skills": 473,
   "severity": "HIGH",
   "title_en": "Destructive filesystem commands on broad paths",
   "title_zh": "对大范围路径的破坏性命令（rm -rf / 格式化等）"
  },
  {
   "id": "SXR001",
   "hits": 846,
   "skills": 327,
   "severity": "CRITICAL",
   "title_en": "Downloads a script and pipes it straight into a shell",
   "title_zh": "下载脚本并直接管道进 shell 执行（curl | bash）"
  },
  {
   "id": "SXR037",
   "hits": 826,
   "skills": 367,
   "severity": "MEDIUM",
   "title_en": "Collects environment variables toward an output or the network",
   "title_zh": "收集环境变量并导出（环境变量里常有密钥）"
  },
  {
   "id": "SXR019",
   "hits": 555,
   "skills": 268,
   "severity": "HIGH",
   "title_en": "Dynamic context injection: shell command runs when skill loads",
   "title_zh": "动态上下文注入：技能加载时即执行 shell 命令（!`cmd`）"
  },
  {
   "id": "SXR023",
   "hits": 543,
   "skills": 155,
   "severity": "HIGH",
   "title_en": "Registers an MCP server (grants the agent a new tool backend)",
   "title_zh": "注册 MCP 服务器（等于给 Agent 接上一个新的工具后端）"
  },
  {
   "id": "SXR005",
   "hits": 495,
   "skills": 192,
   "severity": "CRITICAL",
   "title_en": "Writes persistence: shell profiles, cron, scheduled tasks, registry",
   "title_zh": "植入持久化：改 shell 配置 / cron / 计划任务 / 注册表启动项"
  },
  {
   "id": "SXR033",
   "hits": 494,
   "skills": 401,
   "severity": "MEDIUM",
   "title_en": "Description hides capabilities the skill actually uses",
   "title_zh": "描述未如实披露技能实际具备的能力（网络/执行）"
  }
 ]
};
