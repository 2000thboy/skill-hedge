#!/usr/bin/env python3
"""
hedge-sec-scan.py — Security vulnerability scanner for vibe-coded projects
Part of hedge. Detects common injection & security flaws across languages.

Usage:
    python hedge-sec-scan.py <path> [--format=json|md] [--severity=low|medium|high|critical]
    python hedge-sec-scan.py . --format=md                      # scan current dir, markdown output
    python hedge-sec-scan.py ./src --severity=high              # only high+ findings
    python hedge-sec-scan.py ./src --lang=js,py                 # filter by language

Exit codes:
    0 = no issues found
    1 = issues found (count in stderr)
    2 = bad args / path not found
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "3.0.0"

# ────────────────────────────────
# Detection Rules
# ────────────────────────────────

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str          # critical, high, medium, low
    category: str          # injection, xss, secret, traversal, deserialization, config, regex
    languages: Tuple[str, ...]
    patterns: Tuple[str, ...]
    description: str
    recommendation: str
    # Vibe-coding specific context
    vibe_context: str      # Why vibe coders hit this


RULES: List[Rule] = [
    # ═══════════════════════════════════════
    # SQL Injection (Sec1)
    # ═══════════════════════════════════════
    Rule(
        id="Sec1-A",
        name="SQL Injection — String Concatenation",
        severity="critical",
        category="injection",
        languages=("py", "js", "ts", "java", "php", "go", "rb"),
        patterns=(
            r'execute\s*\(\s*["\'].*\+',
            r'query\s*\(\s*["\'].*\+',
            r'exec\s*\(\s*["\'].*\+',
            r'(?:SELECT|INSERT|UPDATE|DELETE).*%s',
            r'f["\']\s*SELECT\s+.*\{.*\}',
            r'\$\{.*\}.*SELECT|SELECT.*\$\{.*\}',
            r"['\"]SELECT\s+.*\+\s*(?:req\.|request\.|params\.|body\.|query\.|args\[)",
            r'\.format\s*\(\s*.*(?:req\.|request\.|params\.|body\.|query\.)',
            r'"""\s*SELECT\s+.*\.format\s*\(',
            r'cursor\.execute\s*\(\s*["\'].*%\s*(?!\()',
        ),
        description="User input concatenated directly into SQL query",
        recommendation="Use parameterized queries (prepared statements). NEVER concatenate user input into SQL.",
        vibe_context="Vibe coders often ask AI to 'write a search function' and get string-concatenated SQL. They copy-paste without reviewing.",
    ),
    Rule(
        id="Sec1-B",
        name="SQL Injection — Template Literal in Query",
        severity="critical",
        category="injection",
        languages=("js", "ts"),
        patterns=(
            r'`\s*SELECT\s+.*\$\{[^}]+\}',
            r'`\s*INSERT\s+INTO.*\$\{[^}]+\}',
            r'`\s*UPDATE\s+.*\$\{[^}]+\}',
            r'`\s*DELETE\s+FROM.*\$\{[^}]+\}',
            r'knex\.raw\s*\(\s*`.*\$\{',
            r'sequelize\.query\s*\(\s*`.*\$\{',
        ),
        description="JavaScript template literal with variable interpolation inside SQL",
        recommendation="Use query builder parameters or prepared statements. Template literals in SQL are always dangerous.",
        vibe_context="AI loves generating template literals because they look 'clean'. Vibe coders paste them into db.query() without thinking.",
    ),
    Rule(
        id="Sec1-C",
        name="SQL Injection — ORM Raw Query Abuse",
        severity="high",
        category="injection",
        languages=("py", "js", "ts", "rb"),
        patterns=(
            r'\.raw\s*\(\s*["\'].*\+',
            r'\.raw\s*\(\s*f["\']',
            r'session\.execute\s*\(\s*text\s*\(\s*["\'].*\+',
            r'\.createNativeQuery\s*\(\s*["\'].*\+',
            r'ActiveRecord::Base\.connection\.execute\s*\(\s*["\'].*\#\{',
        ),
        description="Using ORM's raw query method with string concatenation defeats ORM protection",
        recommendation="Even with ORMs, raw queries must use parameterized binds. Never concatenate into .raw() or .execute(text(...)).",
        vibe_context="Vibe coders use .raw() when the AI can't figure out ORM syntax. They paste the 'working' SQL without parameterizing.",
    ),

    # ═══════════════════════════════════════
    # Command Injection (Sec2)
    # ═══════════════════════════════════════
    Rule(
        id="Sec2-A",
        name="Command Injection — exec/spawn with user input",
        severity="critical",
        category="injection",
        languages=("py", "js", "ts", "php", "rb", "go"),
        patterns=(
            r'os\.system\s*\(\s*.*(?:req\.|request\.|params\.|body\.|query\.|args\[|input\(|sys\.argv)',
            r'subprocess\.(?:call|run|Popen)\s*\(\s*.*(?:req\.|request\.|params\.|body\.|query\.|args\[)',
            r'child_process\.(?:exec|execSync)\s*\(\s*[`"\'].*\+\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'child_process\.(?:exec|execSync)\s*\(\s*`.*\$\{[^}]+\}',
            r'shell_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)',
            r'backticks\s+.*\#\{(?:params|request|params|body)',
            r'exec\.Command\s*\(\s*.*\+\s*(?:r\.|req\.|request\.|params\.)',
        ),
        description="User input flows into shell command execution",
        recommendation="Use parameterized command lists (e.g., subprocess.run([cmd, arg1, arg2])) instead of shell strings.",
        vibe_context="Vibe coders ask AI to 'run a command with user input' and get os.system() or exec(). They never realize the danger.",
    ),
    Rule(
        id="Sec2-B",
        name="Command Injection — eval with user input",
        severity="critical",
        category="injection",
        languages=("py", "js", "ts", "php"),
        patterns=(
            r'eval\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'exec\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'new\s+Function\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input passed to eval/exec/new Function — arbitrary code execution",
        recommendation="NEVER pass user input to eval() or exec(). Find a safe parser or whitelist approach.",
        vibe_context="AI sometimes suggests eval() as a 'quick fix' for dynamic code. Vibe coders paste it blindly.",
    ),

    # ═══════════════════════════════════════
    # XSS / Reflected Input (Sec3)
    # ═══════════════════════════════════════
    Rule(
        id="Sec3-A",
        name="XSS — innerHTML with user input",
        severity="critical",
        category="xss",
        languages=("js", "ts", "html"),
        patterns=(
            r'\.innerHTML\s*=\s*(?:req\.|request\.|params\.|body\.|query\.|location\.|document\.)',
            r'\.innerHTML\s*=\s*.*\+\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'document\.write\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.|location\.)',
        ),
        description="User input written directly to DOM without sanitization",
        recommendation="Use textContent instead of innerHTML. If HTML is required, use a strict sanitizer like DOMPurify.",
        vibe_context="AI frequently generates innerHTML for dynamic content. Vibe coders copy-paste and ship XSS vulnerabilities.",
    ),
    Rule(
        id="Sec3-B",
        name="XSS — Unescaped Output in Template",
        severity="high",
        category="xss",
        languages=("py", "php", "rb", "js"),
        patterns=(
            r'\{\{\{.*(?:req\.|request\.|params\.|body\.|query\.)',
            r'<\?\=\s*(?:?!htmlspecialchars)\$_(?:GET|POST|REQUEST)',
            r'Jinja2\s*.*\|\s*safe\s*\}\}',
            r'\.html\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="Unescaped user output in template engine",
        recommendation="Use auto-escaping template engines. Explicitly mark safe only after sanitization.",
        vibe_context="Vibe coders use |safe or triple-braces when AI output doesn't render correctly. They disable protection without understanding.",
    ),
    Rule(
        id="Sec3-C",
        name="XSS — Cookie without Secure/HttpOnly",
        severity="medium",
        category="xss",
        languages=("js", "ts", "py", "java", "php"),
        patterns=(
            r'res\.cookie\s*\([^)]*\)\s*(?!.*httpOnly)(?!.*secure)',
            r'set_cookie\s*\([^)]*\)(?!.*[Hh]ttp[Oo]nly)(?!.*[Ss]ecure)',
            r'response\.addCookie\s*\([^)]*\)(?!.*[Hh]ttp[Oo]nly)(?!.*[Ss]ecure)',
        ),
        description="Cookie set without HttpOnly and Secure flags",
        recommendation="Always set httpOnly, secure, and sameSite on cookies. Use __Host- prefix for session cookies.",
        vibe_context="AI-generated auth code often omits cookie flags. Vibe coders don't know these flags exist.",
    ),

    # ═══════════════════════════════════════
    # XSS — Framework-Specific (Sec3-D, Sec3-E)
    # ═══════════════════════════════════════
    Rule(
        id="Sec3-D",
        name="XSS — Vue v-html with User Input",
        severity="critical",
        category="xss",
        languages=("vue",),
        patterns=(
            r'v-html\s*=\s*["\']?\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'v-html\s*=\s*["\']?\s*\{\{[^}]*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="Vue v-html directive with user input — equivalent to innerHTML, allows arbitrary HTML/JS execution",
        recommendation="Avoid v-html with user input. Use {{ }} auto-escaping. If HTML is required, use DOMPurify before v-html.",
        vibe_context="AI generates v-html for 'rich text display' with user content. Vibe coders copy without realizing it's Vue's innerHTML.",
    ),
    Rule(
        id="Sec3-E",
        name="XSS — Svelte {@html} with User Input",
        severity="critical",
        category="xss",
        languages=("svelte",),
        patterns=(
            r'\{@html\s+(?:req\.|request\.|params\.|body\.|query\.)',
            r'\{@html\s+[^}]*\$\{[^}]*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="Svelte {@html} expression with user input — renders raw HTML without escaping",
        recommendation="Never use {@html} with user input. Use regular Svelte expressions { } which auto-escape. Sanitize with DOMPurify if HTML is required.",
        vibe_context="AI uses {@html} for 'rendering HTML content'. Vibe coders paste user input directly into it.",
    ),

    # ═══════════════════════════════════════
    # Path Traversal (Sec4)
    # ═══════════════════════════════════════
    Rule(
        id="Sec4-A",
        name="Path Traversal — File access with user input",
        severity="critical",
        category="traversal",
        languages=("py", "js", "ts", "java", "php", "go", "rb"),
        patterns=(
            r'open\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.|args\[)',
            r'fs\.(?:readFile|readFileSync|writeFile|writeFileSync)\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'path\.join\s*\(\s*__dirname\s*,\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'path\.resolve\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'File\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'readfile\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'os\.ReadFile\s*\(\s*(?:r\.|req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used directly as file path — path traversal vulnerability",
        recommendation="Whitelist allowed files/paths. Use path.basename() and validate against a known list. NEVER use user input directly.",
        vibe_context="Vibe coders ask AI for 'serve a file based on URL parameter' and get fs.readFileSync(req.query.file). Shipped immediately.",
    ),
    Rule(
        id="Sec4-B",
        name="Path Traversal — Zip Slip",
        severity="high",
        category="traversal",
        languages=("py", "js", "ts", "java", "go"),
        patterns=(
            r'extractall\s*\(',
            r'unzip\s*.*\.extract\s*\(',
            r'ZipInputStream\s*.*\.getNextEntry\s*\(',
            r'archive/zip\s*.*\.Extract',
        ),
        description="Zip extraction without validating entry paths — Zip Slip vulnerability",
        recommendation="Validate every zip entry path with path.Clean() and ensure it stays within target directory.",
        vibe_context="AI-generated file upload features often include zip extraction. Vibe coders paste without path validation.",
    ),

    # ═══════════════════════════════════════
    # Insecure Deserialization (Sec5)
    # ═══════════════════════════════════════
    Rule(
        id="Sec5-A",
        name="Insecure Deserialization — pickle/eval/yaml.load",
        severity="critical",
        category="deserialization",
        languages=("py", "js", "java", "rb"),
        patterns=(
            r'pickle\.loads?\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'yaml\.load\s*\(',
            r'YAML\.load\s*\(',
            r'ObjectInputStream\s*.*\.readObject\s*\(',
            r'Marshal\.load\s*\(',
            r'JSON\.parse\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="Untrusted data passed to deserialization function — remote code execution",
        recommendation="Use yaml.safe_load(), json with restricted object_hook, or schema-validated parsing. NEVER deserialize untrusted data with pickle/Java ObjectInputStream.",
        vibe_context="AI suggests pickle or yaml.load for 'quick config loading'. Vibe coders paste into request handlers.",
    ),

    # ═══════════════════════════════════════
    # Hardcoded Secrets (Sec6)
    # ═══════════════════════════════════════
    Rule(
        id="Sec6-A",
        name="Hardcoded Secret — API Key / Token",
        severity="high",
        category="secret",
        languages=("py", "js", "ts", "java", "go", "php", "rb", "yaml", "json", "env"),
        patterns=(
            r'(?i)(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
            r'(?i)(?:auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{16,}["\']',
            r'(?i)(?:secret[_-]?key|private[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9_\-/+=]{16,}["\']',
            r'(?i)aws[_-]?(?:access[_-]?key|secret)[_-]?id\s*[:=]\s*["\'][A-Z0-9]{16,}["\']',
            r'(?i)github[_-]?token\s*[:=]\s*["\']ghp_[a-zA-Z0-9]{36}["\']',
            r'(?i)openai[_-]?api[_-]?key\s*[:=]\s*["\']sk-[a-zA-Z0-9]{32,}["\']',
            r'(?i)password\s*[:=]\s*["\'][^"\']{4,}["\']',
        ),
        description="Hardcoded API key, token, or password in source code",
        recommendation="Use environment variables or a secret manager. NEVER commit secrets to source control.",
        vibe_context="AI-generated examples always include placeholder API keys. Vibe coders replace them with real keys and commit.",
    ),
    Rule(
        id="Sec6-B",
        name="Hardcoded Secret — Database Connection String",
        severity="high",
        category="secret",
        languages=("py", "js", "ts", "java", "go", "php", "rb"),
        patterns=(
            r'(?i)mongodb(\+srv)?://[^:]+:[^@]+@',
            r'(?i)postgres(ql)?://[^:]+:[^@]+@',
            r'(?i)mysql://[^:]+:[^@]+@',
            r'(?i)redis://:[^@]+@',
        ),
        description="Database connection string with embedded password",
        recommendation="Use connection string from environment variable or secret store.",
        vibe_context="AI-generated DB connection examples include 'password123'. Vibe coders paste their real credentials and commit.",
    ),

    # ═══════════════════════════════════════
    # SSRF / Open Redirect (Sec7)
    # ═══════════════════════════════════════
    Rule(
        id="Sec7-A",
        name="SSRF — URL fetch with user input",
        severity="high",
        category="ssrf",
        languages=("py", "js", "ts", "php", "go", "java"),
        patterns=(
            r'(?:requests|axios|fetch|http|https)\.[a-z]+\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'curl\s+.*\$_(?:GET|POST|REQUEST)',
            r'urllib\.(?:request|urlopen)\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'http\.Get\s*\(\s*(?:r\.|req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used as URL for HTTP request — SSRF vulnerability",
        recommendation="Whitelist allowed domains/IPs. Parse URL and validate hostname against allowlist. Block internal IPs.",
        vibe_context="Vibe coders ask AI for 'fetch data from user-provided URL' and get requests.get(req.query.url). No validation.",
    ),
    Rule(
        id="Sec7-B",
        name="Open Redirect — Redirect with user input",
        severity="medium",
        category="ssrf",
        languages=("py", "js", "ts", "php", "java", "go", "rb"),
        patterns=(
            r'res(?:ponse)?\.redirect\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'Redirect\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'header\s*\(\s*["\']Location["\']\s*,\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'response\.sendRedirect\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used in HTTP redirect — phishing/open redirect vulnerability",
        recommendation="Whitelist allowed redirect destinations. Use internal route mapping instead of user-provided URLs.",
        vibe_context="AI generates redirect(req.query.next) for 'login redirect'. Vibe coders don't realize this enables phishing.",
    ),

    # ═══════════════════════════════════════
    # Eval / Exec Abuse (Sec8)
    # ═══════════════════════════════════════
    Rule(
        id="Sec8-A",
        name="Dangerous Function — eval",
        severity="critical",
        category="injection",
        languages=("js", "ts", "php"),
        patterns=(
            r'(?<!\w)eval\s*\(',
            r'new\s+Function\s*\(',
            r'setTimeout\s*\(\s*["\']',
            r'setInterval\s*\(\s*["\']',
        ),
        description="eval() or equivalent dynamic code execution found",
        recommendation="Remove eval(). Use JSON.parse for data, proper parsing for expressions. There is almost always a safer alternative.",
        vibe_context="AI sometimes uses eval() for 'dynamic property access' or parsing. Vibe coders never question it.",
    ),
    Rule(
        id="Sec8-B",
        name="Dangerous Function — exec / compile",
        severity="critical",
        category="injection",
        languages=("py", "rb", "php"),
        patterns=(
            r'(?<!\w)exec\s*\(',
            r'compile\s*\(',
            r'__import__\s*\(',
            r'module_eval\s*\(',
            r'class_eval\s*\(',
        ),
        description="Dynamic code execution function found",
        recommendation="Remove exec/compile/module_eval. These are almost never necessary in production code.",
        vibe_context="AI occasionally generates exec() for 'dynamic imports'. Vibe coders paste and ship without review.",
    ),

    # ═══════════════════════════════════════
    # Insecure Regex / ReDoS (Sec9)
    # ═══════════════════════════════════════
    Rule(
        id="Sec9-A",
        name="ReDoS — Nested Quantifiers in Regex",
        severity="medium",
        category="regex",
        languages=("js", "ts", "py", "java", "go", "rb"),
        patterns=(
            r'\(\?[?:]\s*[\*\+].*\)\s*[\*\+]',
            r'\[.*\]\s*[\*\+]\s*[\*\+]',
            r'\.\*\s*\.\*',
            r'\.\+\s*\.\+',
            r'\([^)]*\|\|?[^)]*\)\s*[\*\+]\s*[\*\+]',
        ),
        description="Regex pattern with nested quantifiers — potential ReDoS (Regular Expression Denial of Service)",
        recommendation="Simplify regex. Avoid nested + and *. Use possessive quantifiers where supported or validate input length first.",
        vibe_context="AI-generated validation regexes are often complex and untested. Vibe coders copy them without checking for ReDoS.",
    ),

    # ═══════════════════════════════════════
    # Debug Mode in Production (Sec10)
    # ═══════════════════════════════════════
    Rule(
        id="Sec10-A",
        name="Debug Mode Enabled",
        severity="medium",
        category="config",
        languages=("py", "js", "ts", "php", "java", "go"),
        patterns=(
            r'(?i)debug\s*[:=]\s*true',
            r'(?i)DEBUG\s*[:=]\s*True',
            r'(?i)app\.run\s*\([^)]*debug\s*=\s*true',
            r'(?i)FLASK_DEBUG\s*[:=]\s*1',
            r'(?i)NODE_ENV\s*[:=]\s*["\']development["\']',
            r'(?i)app\.use\s*\(\s*errorhandler\s*\(\s*',
            r'(?i)detailedErrors\s*[:=]\s*true',
        ),
        description="Debug mode or detailed error messages enabled — information disclosure",
        recommendation="Ensure debug mode is OFF in production. Use environment-based configuration.",
        vibe_context="AI-generated starter code often has debug=True. Vibe coders deploy it to production without changing.",
    ),
    Rule(
        id="Sec10-B",
        name="Stack Trace Exposure",
        severity="medium",
        category="config",
        languages=("js", "ts", "py", "php", "java", "go"),
        patterns=(
            r'(?i)res\.status\(\d+\)\.send\s*\(\s*(?:err\.|error\.|e\.|ex\.)',
            r'(?i)res\.json\s*\(\s*\{[^}]*(?:error|err|stack|trace)',
            r'(?i)return\s+\{[^}]*(?:error|err|stack|trace)',
        ),
        description="Error stack traces or detailed errors sent to client",
        recommendation="Log full errors server-side. Return generic error messages to clients.",
        vibe_context="AI often returns err.stack or err.message directly in API responses. Vibe coders don't sanitize error output.",
    ),

    # ═══════════════════════════════════════
    # CORS Misconfiguration (Sec11)
    # ═══════════════════════════════════════
    Rule(
        id="Sec11-A",
        name="CORS — Overly Permissive",
        severity="medium",
        category="config",
        languages=("js", "ts", "py", "java", "go"),
        patterns=(
            r'(?i)Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\']',
            r'(?i)cors\s*\(\s*\{\s*origin\s*[:=]\s*["\']\*["\']',
            r'(?i)@CrossOrigin\s*\(\s*origins\s*=\s*["\']\*["\']',
            r'(?i)w\.Header\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\']\*["\']',
        ),
        description="CORS configured to allow all origins — CSRF risk for authenticated APIs",
        recommendation="Specify exact origins. Use environment-based allowlist. Never use * for authenticated endpoints.",
        vibe_context="AI often suggests app.use(cors()) or Access-Control-Allow-Origin: * to 'fix CORS errors'. Vibe coders paste without understanding.",
    ),

    # ═══════════════════════════════════════
    # No Input Validation (Sec12)
    # ═══════════════════════════════════════
    Rule(
        id="Sec12-A",
        name="Missing Input Validation",
        severity="high",
        category="injection",
        languages=("js", "ts", "py", "php", "go", "java", "rb"),
        patterns=(
            r'(?:req\.|request\.|params\.|body\.|query\.)\w+\s*\)',  # direct use without validation
        ),
        # This is a heuristic - we check context around the match
        description="User input used directly without visible validation",
        recommendation="Always validate and sanitize user input. Use schema validation (Zod, Joi, pydantic, validator).",
        vibe_context="Vibe coders take AI output that chains req.body straight to DB operations. No validation layer exists.",
    ),

    # ═══════════════════════════════════════
    # Vibe-Coding Specific Patterns
    # ═══════════════════════════════════════
    Rule(
        id="Vibe1-A",
        name="AI Slop — Trust User Input for File Operations",
        severity="high",
        category="traversal",
        languages=("js", "ts", "py"),
        patterns=(
            r'fs\.unlink(?:Sync)?\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'fs\.rmdir(?:Sync)?\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'os\.remove\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'shutil\.(?:rmtree|rm_tree)\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used for file deletion — can delete arbitrary files",
        recommendation="NEVER use user input for file deletion. Use a mapping table of allowed operations.",
        vibe_context="AI sometimes generates 'delete user file' endpoints that take filename from query param. Vibe coders ship it.",
    ),
    Rule(
        id="Vibe2-A",
        name="AI Slop — NoSQL Injection",
        severity="critical",
        category="injection",
        languages=("js", "ts", "py"),
        patterns=(
            r'\.find\s*\(\s*\{\s*\$where\s*:',
            r'\.find\s*\(\s*\{\s*\$ne\s*:',
            r'db\.[a-zA-Z]+\.find\s*\(\s*\{\s*\$',
            r'\.findOne\s*\(\s*\{\s*\$',
            r'aggregate\s*\(\s*\[\s*\{\s*\$match\s*:\s*\{[^}]*\$',
        ),
        description="NoSQL query with $ operators from user input — NoSQL injection",
        recommendation="Use parameterized NoSQL queries. Sanitize or whitelist allowed operators. Never pass user objects directly to find().",
        vibe_context="AI generates MongoDB.find(req.body) for 'flexible search'. Vibe coders paste and ship NoSQL injection.",
    ),
    Rule(
        id="Vibe3-A",
        name="AI Slop — Trust User Input for ID/Key",
        severity="medium",
        category="injection",
        languages=("js", "ts", "py", "php", "go", "java"),
        patterns=(
            r'\.findById\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'\.findByPk\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'\.findOne\s*\(\s*\{\s*id\s*:\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'\.where\s*\(\s*["\']id["\']\s*,\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used directly as database ID without type validation",
        recommendation="Validate ID format (UUID pattern, integer, ObjectId) before querying. Use ORM's type-safe methods.",
        vibe_context="AI generates User.findById(req.params.id). Vibe coders don't validate that id is actually a valid ObjectId/UUID.",
    ),

    # ═══════════════════════════════════════
    # CLI/API Argument Misuse (Sec13) — from recurring-cli-api-confusion
    # ═══════════════════════════════════════
    Rule(
        id="Sec13-A",
        name="CLI/API — Raw argv Access Without Bounds Check",
        severity="medium",
        category="config",
        languages=("py", "js", "ts", "go", "rb"),
        patterns=(
            r'sys\.argv\[\d+\]',
            r'process\.argv\[\d+\]',
            r'os\.Args\[\d+\]',
            r'ARGV\[\d+\]',
        ),
        description="Raw argv indexed access without checking length — IndexError/undefined on missing args",
        recommendation="Use argparse/click (Python), yargs/minimist (JS), or clap (Go). If using raw argv, check len(argv) before indexing.",
        vibe_context="AI generates sys.argv[1] without checking if any arguments were provided. Vibe coders run it with no args and get IndexError.",
    ),

    # ═══════════════════════════════════════
    # State Management Security (Sec14) — from recurring-state-management
    # ═══════════════════════════════════════
    Rule(
        id="Sec14-A",
        name="State Management — External Input as State Key",
        severity="high",
        category="injection",
        languages=("js", "ts", "py"),
        patterns=(
            r'state\[\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'setState\s*\(\s*\{?\s*\[\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'useState\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'dispatch\s*\(\s*\{[^}]*type\s*:\s*["\'][^"\']*["\'][^}]*payload\s*:\s*(?:req\.|request\.|params\.|body\.|query\.)',
            r'store\.[a-zA-Z]+\s*=\s*(?:req\.|request\.|params\.|body\.|query\.)',
        ),
        description="User input used directly as state key or state value — can corrupt application state",
        recommendation="Whitelist allowed state keys. Validate and sanitize before updating state. Use typed state management.",
        vibe_context="AI generates state[req.params.key] = value for 'dynamic state updates'. Vibe coders don't realize this allows arbitrary state mutation.",
    ),
    Rule(
        id="Sec14-B",
        name="State Management — Multiple State Sources Without Sync",
        severity="medium",
        category="config",
        languages=("js", "ts", "py", "go"),
        patterns=(
            r'(?i)state\.(?:[a-zA-Z_]+\.)*status\s*[=:]',
            r'(?i)completed\s*[=:]\s*(?:true|false)',
            r'(?i)stage\.status\s*[=:]',
            r'(?i)pipeline\.[a-zA-Z]+\.status\s*[=:]',
        ),
        description="Multiple status/completion flags without centralized schema — state drift risk",
        recommendation="Use a single source of truth for state. Define a Schema. All status updates go through one function.",
        vibe_context="AI generates pipeline stages with separate completion flags. Vibe coders add more without centralizing, leading to inconsistent state.",
    ),
]

# ────────────────────────────────
# File Extension → Language Mapping
# ────────────────────────────────

EXT_MAP: Dict[str, str] = {
    ".py": "py", ".js": "js", ".ts": "ts", ".jsx": "js", ".tsx": "ts",
    ".java": "java", ".php": "php", ".go": "go", ".rb": "rb",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".env": "env",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
}

SKIP_DIRS = {
    "node_modules", "venv", ".venv", "__pycache__", ".git", ".github",
    "dist", "build", ".next", ".nuxt", "coverage", ".coverage",
    "vendor", "target", "bin", "obj", ".idea", ".vscode",
}

# ────────────────────────────────
# Result Types
# ────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    file: str
    line: int
    column: int
    match: str
    context: str
    description: str
    recommendation: str
    vibe_context: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    version: str
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def by_severity(self) -> Dict[str, List[Finding]]:
        d: Dict[str, List[Finding]] = {"critical": [], "high": [], "medium": [], "low": []}
        for f in self.findings:
            d.setdefault(f.severity, []).append(f)
        return d


# ────────────────────────────────
# Scan Logic
# ────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def should_skip_dir(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def get_context(lines: List[str], line_idx: int, radius: int = 2) -> str:
    start = max(0, line_idx - radius)
    end = min(len(lines), line_idx + radius + 1)
    context_lines = []
    for i in range(start, end):
        marker = ">>> " if i == line_idx else "    "
        context_lines.append(f"{marker}{i + 1:4d} | {lines[i].rstrip()}")
    return "\n".join(context_lines)


def scan_file(file_path: Path, rules: List[Rule], min_severity: str) -> List[Finding]:
    findings: List[Finding] = []
    ext = file_path.suffix.lower()
    lang = EXT_MAP.get(ext)
    if lang is None:
        return findings

    # Filter rules by language and severity
    min_rank = SEVERITY_ORDER.get(min_severity, 0)
    applicable = [
        r for r in rules
        if lang in r.languages and SEVERITY_ORDER.get(r.severity, 99) <= min_rank
    ]
    if not applicable:
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = content.splitlines()

    for rule in applicable:
        for pattern in rule.patterns:
            try:
                for match in re.finditer(pattern, content):
                    # Map match position to line/column
                    pos = match.start()
                    line_idx = content[:pos].count("\n")
                    col = pos - content.rfind("\n", 0, pos) - 1
                    if line_idx >= len(lines):
                        continue

                    line_text = lines[line_idx]
                    # Skip comment lines (basic heuristic)
                    stripped = line_text.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*") or stripped.startswith("*"):
                        continue

                    # Skip if it's in rule metadata strings (vibe_context, description, recommendation)
                    # These are educational text, not actual vulnerable code
                    if any(field in stripped for field in ("vibe_context=", "description=", "recommendation=")):
                        continue
                    # Skip raw regex pattern strings (they're detection signatures, not vulnerable code)
                    if stripped.startswith(("r'", 'r"', "r'''", 'r"""')):
                        continue
                    # Skip regular string literals that look like patterns (heuristic: starts with quote + contains regex metachars)
                    if re.search(r'^\s*[\'"]', stripped) and stripped.count('\\') >= 2:
                        continue

                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        file=str(file_path),
                        line=line_idx + 1,
                        column=col + 1,
                        match=match.group(0)[:120],
                        context=get_context(lines, line_idx),
                        description=rule.description,
                        recommendation=rule.recommendation,
                        vibe_context=rule.vibe_context,
                    ))
            except re.error:
                continue

    # Deduplicate by (file, line, rule_id)
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def scan_directory(target: Path, rules: List[Rule], min_severity: str, lang_filter: Optional[List[str]]) -> ScanResult:
    import time
    start = time.time()
    result = ScanResult(target=str(target.resolve()), version=VERSION)

    if target.is_file():
        files = [target]
    else:
        files = []
        for root, _, filenames in os.walk(target):
            root_path = Path(root)
            if should_skip_dir(root_path):
                continue
            for name in filenames:
                fp = root_path / name
                ext = fp.suffix.lower()
                if ext not in EXT_MAP:
                    continue
                if lang_filter and EXT_MAP[ext] not in lang_filter:
                    continue
                files.append(fp)

    for fp in files:
        try:
            findings = scan_file(fp, rules, min_severity)
            result.findings.extend(findings)
            result.files_scanned += 1
            with open(fp, "rb") as f:
                result.lines_scanned += sum(1 for _ in f)
        except Exception as e:
            result.errors.append(f"{fp}: {e}")

    result.duration_ms = (time.time() - start) * 1000
    return result


# ────────────────────────────────
# Output Formatters
# ────────────────────────────────

def format_md(result: ScanResult) -> str:
    lines = [
        "# 🛡️ Hedge Security Scan Report",
        "",
        f"**Target:** `{result.target}`",
        f"**Version:** {result.version}",
        f"**Files Scanned:** {result.files_scanned}",
        f"**Lines Scanned:** {result.lines_scanned:,}",
        f"**Duration:** {result.duration_ms:.0f}ms",
        "",
        "## Summary",
        "",
    ]

    by_sev = result.by_severity
    total = len(result.findings)
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev in ("critical", "high", "medium", "low"):
        c = len(by_sev.get(sev, []))
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
        lines.append(f"| {emoji} {sev.capitalize()} | {c} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if total == 0:
        lines.append("✅ No security issues found!")
        return "\n".join(lines)

    # Group by category
    by_cat: Dict[str, List[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat, findings in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        lines.append(f"## {cat.upper()} ({len(findings)})")
        lines.append("")
        for f in findings:
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
            lines.append(f"### {sev_emoji} [{f.rule_id}] {f.rule_name}")
            lines.append(f"- **File:** `{f.file}:{f.line}:{f.column}`")
            lines.append(f"- **Severity:** {f.severity.upper()}")
            lines.append(f"- **Match:** `{f.match}`")
            lines.append(f"- **Description:** {f.description}")
            lines.append(f"- **Fix:** {f.recommendation}")
            lines.append(f"- **Why Vibe Coders Hit This:** {f.vibe_context}")
            lines.append("```")
            lines.append(f.context)
            lines.append("```")
            lines.append("")

    if result.errors:
        lines.append("## Errors")
        for e in result.errors:
            lines.append(f"- {e}")

    lines.append("---")
    lines.append(f"*Generated by hedge-sec-scan v{VERSION}*")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps({
        "target": result.target,
        "version": result.version,
        "files_scanned": result.files_scanned,
        "lines_scanned": result.lines_scanned,
        "duration_ms": result.duration_ms,
        "findings": [f.to_dict() for f in result.findings],
        "summary": {
            "critical": len(result.by_severity.get("critical", [])),
            "high": len(result.by_severity.get("high", [])),
            "medium": len(result.by_severity.get("medium", [])),
            "low": len(result.by_severity.get("low", [])),
            "total": len(result.findings),
        },
        "errors": result.errors,
    }, indent=2, ensure_ascii=False)


# ────────────────────────────────
# CLI
# ────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hedge-sec-scan",
        description="Security vulnerability scanner for vibe-coded projects — part of hedge",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Minimum severity to report")
    parser.add_argument("--lang", help="Comma-separated language filter (e.g., js,py)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    lang_filter = args.lang.split(",") if args.lang else None

    result = scan_directory(target, RULES, args.severity, lang_filter)

    if args.format == "json":
        print(format_json(result))
    else:
        print(format_md(result))

    if result.findings:
        critical = len(result.by_severity.get("critical", []))
        high = len(result.by_severity.get("high", []))
        print(f"\n⚠️  Found {len(result.findings)} issues ({critical} critical, {high} high)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
