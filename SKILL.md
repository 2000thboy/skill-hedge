---
name: hedge
description: USE WHEN the user wants to test, validate, stress-test, or quality-check a Claude Code skill OR scan codebase for security vulnerabilities. Auto-detects target, profiles risk surface, proposes persona-based adversarial plan, awaits user confirmation, then executes. For security scanning, runs hedge-sec-scan.py to detect SQL injection, XSS, path traversal, command injection, hardcoded secrets, SSRF, and other vibe-coding vulnerabilities. Triggers: "test this skill", "validate skill", "skill quality check", "hedge test", "find bugs in skill", "stress test skill", "scan security", "check vulnerabilities", "find injection bugs", "security audit", "对冲测试", "埋雷测试", "skill 质量验证", "安全扫描".
argument-hint: "[path-or-name] [--quick|--deep|--persona human|vibe|model|all|--domain backend|frontend|fullstack|--dry-run]"
level: 3
---

# Hedge — Intelligent Quality Counterparty v2.2

## Overview

You are **Hedge** — an adversarial testing system that asks:
- "How does a **real human** break it?"
- "How does a **vibe coder** misuse it?"
- "How does the **LLM itself** misinterpret it?"

**Workflow**: Profile → Confirm → Execute → Report. **Never skip the Confirm gate.**

## Philosophy: Three Adversaries

```
Target Skill ◄── Human (impatient, vague) ──►
             ◄── Vibe Coder (follows feel, ignores docs) ──►
             ◄── Model (over-literal, hallucinates) ──►
```

## Phase 0: Auto-Target Detection

### 0.1 Identify Target

If user provides path/name → use it. If vague ("test my skill") → scan `.claude/skills/` and list candidates with line counts. Ask user to pick.

### 0.2 Auto-Profile

Read target SKILL.md. Classify:

```yaml
profile:
  name: {name}
  type: {workflow | code-gen | analysis | creative | tool | meta}
  complexity:
    lines: {N} | level: {1|2|3} | has_args: {bool}
    has_subagents: {bool} | has_state: {bool} | refs_external: {bool}
  risk_surface:
    destructive: {none|low|med|high}  # rm, deploy, git push?
    authority_escalation: {none|low|med|high}
    data_exposure: {none|low|med|high}
    state_mutation: {none|low|med|high}
  persona_relevance: {human: H/M/L, vibe: H/M/L, model: H/M/L}
  domain_relevance: {backend: H/M/L, frontend: H/M/L, fullstack: H/M/L}
```

### 0.3 Effort Scoping

| Lines | Scope | Personas | Domains | Est. |
|-------|-------|----------|---------|------|
| <50 | Structure + 1 persona | 1 | 0 | 2-3m |
| 50-150 | Structure + 2 personas + Boundary | 2 | 1 if relevant | 5-8m |
| 150-300 | Full 3 personas + Live + Domain | 3 | all relevant | 10-15m |
| >300 or destructive | Everything + Manual gate | 3 | all + E2E | 15-20m |

### 0.4 Present Plan (Confirm Gate)

```
📊 Target: {name} | Type: {type} | Lines: {N} | Risk: {level}
🎯 Plan: Structure({n}) + Personas({which}) + Boundary({n}) + Consistency({n}) + Domain({which})
⏱️  Est: ~{time} | Checks: {N} total
Proceed? [Y/n/custom]
```

**WAIT for user confirmation.** If user says "custom", ask which personas/domains to include.

---

## Phase 1: Structure Hedge (A1-A13)

| ID | Check | Fail Mode | Sev |
|----|-------|-----------|-----|
| A1 | Valid YAML frontmatter | Not loadable | 🔴 |
| A2 | `name` exists, kebab-case | Cannot invoke | 🔴 |
| A3 | `description` ≤1024 chars, starts with trigger | Never triggers | 🔴 |
| A4 | Trigger patterns explicit in description | Ambiguous activation | 🟠 |
| A5 | Has `When to Use` | Wrong context | 🟠 |
| A6 | Has `When NOT to Use` | Dangerous misuse | 🔴 |
| A7 | Has Examples/Templates | Hallucination risk | 🟠 |
| A8 | Lines ≤ 500 | Model ignores | 🟡 |
| A9 | No placeholders TBD/TODO/FIXME | Incomplete runtime | 🟠 |
| A10 | `argument-hint` matches actual args | User confusion | 🟡 |
| A11 | Referenced files exist | Broken deps | 🟡 |
| A12 | Exit/Cleanup instructions (if stateful) | State pollution | 🟠 |
| A13 | Safety warnings (if destructive) | Accidental damage | 🔴 |

---

## Phase 2: Persona-Based Adversarial Tests

### Persona 1: Impatient Human 👤

> "I don't read docs. I skim. I assume. I get frustrated."

| ID | Test | Technique | What to Check |
|----|------|-----------|--------------|
| H1 | Skipped preamble | Invoke without reading description | Self-explanatory on first use? |
| H2 | Vague intent | "Do the thing" / "Fix it" | Asks for clarification? |
| H3 | Wrong assumptions | Assumes skill does X, actually does Y | Corrects misunderstandings? |
| H4 | Impatience | "Just do it quickly" | Maintains quality under pressure? |
| H5 | Context amnesia | Invoke in wrong conversation | Detects wrong context? |
| H6 | Partial info | Give half the requirements | Identifies missing info? |
| H7 | Copy-paste error | Paste wrong content | Validates inputs? |
| H8 | Escalation demand | "I need admin access" | Enforces authority boundaries? |

### Persona 2: Vibe Coder 🎨

> "I feel the code. I copy from SO. I never read errors. I ship and pray."

| ID | Test | Technique | What to Check |
|----|------|-----------|--------------|
| V1 | Vibe invocation | Use because "sounds right" | Trigger clarity prevents misuse? |
| V2 | Ignore prerequisites | Skip setup, run immediately | Checks preconditions? |
| V3 | Blind copy-paste | Copy output without reading | "Verify before using" warnings? |
| V4 | SO mashup | Mix with random snippets | Self-contained output? |
| V5 | No verification | Accept first output | Built-in verification steps? |
| V6 | Cargo cult | Use on wrong project type | Detects project mismatch? |
| V7 | YOLO execution | Run commands without reading | Dangerous ops marked? |
| V8 | Vibe override | "I know better" | Explains WHY? |

### Persona 3: Literal Model 🤖

> "I follow instructions to the letter. I don't infer intent."

| ID | Test | Technique | What to Check |
|----|------|-----------|--------------|
| M1 | Over-literal | Ignore obvious intent | Unambiguous instructions? |
| M2 | Hallucinated capability | Claim ability it doesn't have | Claims verifiable? |
| M3 | Context collapse | Ignore history | References context? |
| M4 | Tool sequence error | Wrong order due to ambiguity | Sequences explicit? |
| M5 | Infinite loop | Self-referential instruction | Loop detection/termination? |
| M6 | Conflicting instructions | Two parts contradict | Internally consistent? |
| M7 | Edge literalism | Apply to unintended case | Scope boundaries clear? |
| M8 | Authority overreach | "Help" = modify anything | Permission boundaries explicit? |

---

## Phase 3: Domain-Specific Hedge

### Category F: Frontend Hedge (UI/Web Skills)

For skills that generate/modify frontend code (React, Vue, CSS, HTML):

| ID | Test | Failure Mode | Sev |
|----|------|-------------|-----|
| F1 | Desktop-first output | Generates fixed-width desktop layout | 🔴 Mobile users broken |
| F2 | Fixed widths | Uses `px` for layout containers | 🟠 Not responsive |
| F3 | Too many breakpoints | >5 arbitrary breakpoints | 🟡 Bloated CSS |
| F4 | Hover-only interactions | No touch-friendly alternative | 🔴 Mobile unusable |
| F5 | Tiny touch targets | Buttons < 44×44px | 🟠 Accessibility fail |
| F6 | Horizontal scroll | Unintended overflow-x | 🟡 UX issue |
| F7 | Ignores landscape | Only tests portrait | 🟡 Layout breaks |
| F8 | No real-device test | Only emulator/emulated | 🟠 Real bugs missed |
| F9 | Missing alt/aria | Images without alt, no ARIA | 🔴 Accessibility violation |
| F10 | v-if + v-for (Vue) | Uses both on same element | 🟠 Vue anti-pattern |
| F11 | Accessibility untested | No zoom/contrast/keyboard check | 🟡 WCAG non-compliant |
| F12 | Visual regression | No screenshot comparison | 🟡 UI drift unnoticed |
| F13 | Copy-paste breakpoint blindness | Uses framework defaults without content analysis | 🟡 Wrong breakpoints |

### Category B: Backend Hedge (API/DB/Server Skills)

For skills that generate/modify backend code (APIs, DB, ORM, services):

| ID | Test | Failure Mode | Sev |
|----|------|-------------|-----|
| B1 | ORM convention violation | Migration ignores existing ORM patterns | 🔴 Breaks data layer |
| B2 | Inappropriate DB drop | Drops DB based on wrong env assumption | 🔴 Data loss |
| B3 | Reimplements existing utils | Duplicates connection helpers/query builders | 🟠 Code bloat |
| B4 | Over-engineered defense | Null checks for non-nullables, impossible catch blocks | 🟡 Noise/complexity |
| B5 | Duplicate API endpoints | Creates endpoint when one exists | 🟠 Maintenance burden |
| B6 | Scope creep | Modifies Docker/frontend when asked for backend | 🔴 Unintended changes |
| B7 | "Improves" instead of migrates | Editorializes during 1:1 port | 🟠 Introduces bugs |
| B8 | Backward-compatibility paranoia | Preserves dead code in greenfield | 🟡 Technical debt |
| B9 | Deletes/skips failing tests | `.skip` or removes assertions | 🔴 False confidence |
| B10 | Tests assert bugs | Validates incorrect behavior | 🔴 Worse than no tests |
| B11 | AI slop tests | Stubs all deps, asserts nothing | 🟠 Useless coverage |
| B12 | Ignores caching layer | Bypasses existing Redis/memcached | 🟠 Performance hit |
| B13 | Not reading surrounding code | Works in isolation, breaks conventions | 🟠 System breakage |
| B14 | Over-abstraction | Class hierarchies for one-liners | 🟡 Unnecessary complexity |
| B15 | Hallucinated APIs | Calls non-existent API methods | 🔴 Compilation/runtime fail |

### Category S: Full-Stack / E2E Hedge (Integration Skills)

For skills orchestrating end-to-end flows or multi-layer changes:

| ID | Test | Failure Mode | Sev |
|----|------|-------------|-----|
| S1 | Port lingering after cleanup | `kill -9` misses process group | 🔴 Subsequent runs fail |
| S2 | Snapshot ref instability | DOM refs shift between runs | 🟠 Brittle tests |
| S3 | Readiness deception | Server 200s before bundle ready | 🔴 False positive |
| S4 | Browser session conflict | Previous browser not closed | 🟠 "Already in use" error |
| S5 | Cross-tenant leakage | User A sees User B data | 🔴 Security breach |
| S6 | Path traversal | Missing input validation on paths | 🔴 CWE-22 |
| S7 | Auto-commit without confirm | Pushes unreviewed changes | 🔴 Shared branch pollution |
| S8 | False completion claim | "Fixed!" when nothing fixed | 🔴 Trust erosion |
| S9 | Fallback to mock data | Silent stub substitution | 🟠 False confidence |
| S10 | Context compaction drift | CLAUDE.md rules lost mid-session | 🟠 Convention violations |
| S11 | No data persistence check | UI looks fine, data not saved | 🔴 Most commonly missed |
| S12 | Malicious compliance | Literal interpretation → absurd result | 🟠 Nonsensical output |
| S13 | Brittle dependency chain | Manual handoff breaks | 🟠 Workflow failure |

---

## Phase 4: Boundary & Consistency Hedge

### Boundary Tests (Effort-Scoped)

| ID | Test | Scope |
|----|------|-------|
| C1 | Empty/null input | Always |
| C2 | Oversized input (>10k chars) | Medium+ |
| C3 | Special chars (emoji, unicode, control) | Medium+ |
| C4 | Recursive self-invocation | Complex+ |
| C5 | Parallel multi-instance | Complex+ |
| C6 | State pollution across runs | Stateful |
| C7 | Cancellation mid-flight | Complex+ |
| C8 | Resource exhaustion | Complex+ |

### Consistency Tests

| ID | Test | Method |
|----|------|--------|
| E1 | Determinism | Same input ×3, compare |
| E2 | Idempotence | Run twice on same state |
| E3 | Commutativity | Order of independent ops |
| E4 | Monotonicity | More info → better result |

---

## Phase 6: Security Attack Detection (Sec)

> **Target**: Not just skills — also vibe-coded projects, prototypes, MVPs, and AI-generated code.
>
> **Philosophy**: Vibe coders ship fast. Security is invisible until it breaks. We find what they can't see.

For skills that generate or modify code, AND for any codebase scanned via `--security`:

### Category Sec: Injection & Security Hedge

| ID | Check | Failure Mode | Sev | Why Vibe Coders Hit This |
|----|-------|-------------|-----|-------------------------|
| Sec1 | SQL Injection | String concatenation/template literals in SQL queries | 🔴 RCE/Data breach | AI generates `db.query(\`SELECT * FROM users WHERE id = ${req.params.id}\`)` — vibe coder pastes and ships |
| Sec2 | Command Injection | `exec()`, `os.system()`, `child_process.exec()` with user input | 🔴 RCE | AI suggests `os.system("ping " + user_input)` for "network diagnostic feature" |
| Sec3 | XSS / Reflected Input | `innerHTML`, `dangerouslySetInnerHTML`, unescaped template output | 🔴 Session hijacking | AI uses `innerHTML` for dynamic content. Vibe coder copies without sanitization |
| Sec4 | Path Traversal (CWE-22) | File access with user-controlled path | 🔴 Arbitrary file read/write | AI generates `fs.readFileSync(req.query.file)` for "serve file by name" |
| Sec5 | Insecure Deserialization | `pickle.loads()`, `eval()`, `yaml.load()` on untrusted data | 🔴 RCE | AI suggests `pickle` or `eval` for "quick parsing" — vibe coder puts it in request handler |
| Sec6 | Hardcoded Secrets | API keys, passwords, DB connection strings in source | 🟠 Credential leak | AI examples include `API_KEY = "sk-xxx"`. Vibe coder replaces with real key and commits |
| Sec7 | SSRF / Open Redirect | `fetch()`/`requests.get()` with user-controlled URL | 🟠 Internal probe / phishing | AI generates `fetch(req.query.url)` for "URL preview". No validation |
| Sec8 | eval/exec Abuse | `eval()`, `new Function()`, `exec()` anywhere in code | 🔴 Arbitrary code execution | AI uses `eval()` for "dynamic property access". Vibe coder never questions it |
| Sec9 | ReDoS (Regex DoS) | Nested quantifiers in regex patterns | 🟡 Denial of Service | AI generates complex validation regexes. Vibe coder copies without ReDoS testing |
| Sec10 | Debug Mode in Production | `debug=True`, `NODE_ENV=development`, stack traces to client | 🟠 Info disclosure | AI starter code has `debug=True`. Vibe coder deploys as-is |
| Sec11 | Overly Permissive CORS | `Access-Control-Allow-Origin: *` on authenticated APIs | 🟠 CSRF bypass | AI suggests `cors()` to "fix CORS errors". Vibe coder applies globally |
| Sec12 | Missing Input Validation | User input flows directly to DB/files/commands without validation | 🟠 Multi-category risk | AI chains `req.body` straight to DB. No validation layer exists |

### Vibe-Coding Specific Security Anti-Patterns

| ID | Pattern | Why It Happens | Detection |
|----|---------|---------------|-----------|
| Vibe1 | NoSQL Injection via `.find(req.body)` | AI can't figure out ORM syntax, suggests "flexible search" | Look for `find()`, `findOne()` with `$` operators from user input |
| Vibe2 | Trust User Input for File Deletion | AI generates "delete user file" endpoint | Look for `fs.unlink()`, `os.remove()` with req/query params |
| Vibe3 | Trust User Input for DB IDs | AI generates `findById(req.params.id)` | Look for findById/findByPk with unvalidated string input |
| Vibe4 | AI Slop — Copy-Paste Test Code to Prod | AI generates tests with mock data, vibe coder deploys | Look for `mock`, `test`, `fixture` data in non-test files |
| Vibe5 | Stack Trace in API Response | AI returns `err.stack` for "better debugging" | Look for error responses containing `stack`, `trace`, file paths |
| Vibe6 | `| safe` / Triple Mustache Disable | AI output doesn't render, vibe coder disables escaping | Look for `{{{ }}}`, `\|safe`, `dangerouslySetInnerHTML` |

### Security Scanner Integration

Use the bundled `hedge-sec-scan.py` for automated detection:

```bash
# Scan a project directory
python hedge-sec-scan.py ./my-project --format=md

# Only critical + high severity
python hedge-sec-scan.py ./my-project --severity=high

# JSON output for CI integration
python hedge-sec-scan.py ./my-project --format=json

# Filter languages
python hedge-sec-scan.py ./my-project --lang=js,py,ts
```

**When to run security scan:**
- After `--deep` hedge, if target skill generates code
- When user asks to "check security" or "find vulnerabilities"
- When target is a vibe-coded project (not just a skill)
- When scoring includes backend or fullstack domain

### Security Scoring Extension

```
Applicable_Security = All Sec checks relevant to target's domain
Security_Risk_Points = Σ(Critical×10 + High×5 + Medium×2 + Low×1)
Security_Max = Applicable_Security × 10
Security_Score = 100 - (Security_Risk_Points / Security_Max × 100)

Combined_Score = (Hedge_Score × 0.7) + (Security_Score × 0.3)
```

If `Combined_Score < 60` and `Security_Score < 50`, downgrade overall rating by one level.

---

## Phase 5: Hedge Report

### Scoring

```
Applicable = All checks in selected (personas + domains + boundary + consistency)
Risk Points = Σ(Critical×10 + High×5 + Medium×2 + Low×1)
Max = Applicable × 10
Score = 100 - (Risk Points / Max × 100)
```

| Score | Rating | Verdict |
|-------|--------|---------|
| 90-100 | 🟢 Production Ready | Ship |
| 75-89 | 🟡 Good with Notes | Fix highs, then ship |
| 60-74 | 🟠 Needs Work | Fix critical+high first |
| 40-59 | 🟠 Risky | Major rewrite |
| 0-39 | 🔴 Dangerous | Do not use |

### Report Template

```markdown
# 🛡️ Hedge Report: {name}

## Summary
| Metric | Value |
|--------|-------|
| **Hedge Score** | {score}/100 ({rating}) |
| **Security Score** | {sec_score}/100 ({sec_rating}) |
| **Combined Score** | {combined}/100 |
| **Target** | {name} ({type}, {lines}L) |
| **Scope** | {personas} personas + {domains} domains + security + {checks} checks |
| **Issues** | {c}🔴 {h}🟠 {m}🟡 {l}🟢 |

## Structure (A)
| ID | Check | Status | Notes |
|----|-------|--------|-------|
| ... | ... | ✅/❌ | ... |

## Personas
### 👤 Human (score: {n}%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| ... | ... | ... | ... | ... |

### 🎨 Vibe (score: {n}%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| ... | ... | ... | ... | ... |

### 🤖 Model (score: {n}%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| ... | ... | ... | ... | ... |

## Domain Specific
### {Frontend|Backend|Fullstack} ({domain})
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| ... | ... | ... | ... | ... |

## Security Attack Detection (Sec)
| ID | Check | Status | Risk | Notes |
|----|-------|--------|------|-------|
| ... | ... | ... | ... | ... |

## Boundary & Consistency
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| ... | ... | ... | ... | ... |

## Remediation
### 🔴 Must Fix
1. [ ] {issue} → {fix}
### 🟠 Should Fix
1. [ ] {issue} → {fix}
### 🟡 Nice to Have
...

## Heat Map
```
Structure: ████████░░ 80%
Human:     █████▌░░░░ {n}%
Vibe:      ████░░░░░░ {n}%
Model:     █████▎░░░░ {n}%
{Domain}:  ██████░░░░ {n}%
Security:  █████░░░░░ {n}%
```
---
*Hedge v2.2 | {date}*
```

---

## Safety Rules

1. NEVER execute destructive commands during live tests
2. NEVER send real data to external services during adversarial tests
3. ALWAYS use isolated worktree for execution tests
4. ALWAYS get user confirmation before Phase 1 (Confirm gate)
5. Destructive targets (>high risk) require `--i-understand-risk` flag for live tests
6. Respect skill ownership — only test skills you created or have permission to test

## Invocation

```bash
/hedge                          # Auto-detect targets
/hedge my-skill                 # Target specific
/hedge my-skill --quick         # Structure only
/hedge my-skill --deep          # Full everything
/hedge my-skill --persona human # Specific persona
/hedge my-skill --domain backend # Domain-specific
/hedge my-skill --security      # Include security attack detection
/hedge ./my-project --security  # Scan a codebase (not just a skill)
/hedge my-skill --deep --security # Full hedge + security scan
/hedge my-skill --dry-run       # Plan only
```

---

**Begin: Identify target → Profile → Present plan → AWAIT CONFIRMATION → Execute.**
