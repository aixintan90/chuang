---
name: "🔎 Missed threat or false positive · 漏报或误报"
about: A skill skillxray graded wrong · skillxray 判错了的技能
labels: rules
---

**Which way did it get it wrong?** · **哪种错？**

- [ ] Missed a threat (false negative) · 漏报了一个威胁
- [ ] Flagged something clean (false positive) · 把干净的东西误报了

**The skill** · **技能**

Repo / path, or paste the relevant `SKILL.md` snippet (redact anything private):

```
paste here
```

**What skillxray said vs. what it should say** · **实际 vs. 期望**

e.g. "graded A, but line 12 exfiltrates ~/.ssh" — or — "flagged SXR002 CRITICAL,
but that line is a doc quoting the attack to warn against it".

**Command** · **命令**

```
skillxray scan ...
```
