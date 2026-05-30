# Skill-Hedge

> 软件对冲测试框架 —— 用对抗视角验证代码与系统的质量

---

## 项目简介

**Skill-Hedge** 是一个对抗性质量测试框架，覆盖两个层面：

1. **Skill 层** —— 验证 Claude Code Skill 在面对真实用户误用、模糊意图和模型过度字面化时，是否依然安全、可靠、可用
2. **软件层** —— 扫描前后端代码中的安全漏洞，特别是 AI 生成代码（vibe-coding）中常见的注入攻击、路径遍历、XSS、SSRF 等风险

不同于传统的代码测试工具（如 `auto-verify`、`ultraqa` 验证代码正确性），Skill-Hedge 问的是：**"这段代码在真实攻击者手里会出事吗？"**

核心理念：每个系统都有三个"对手"在等着打破它。Skill-Hedge 就是帮你提前找到这些破绽。

---

## 核心概念

### 三个对手（Three Adversaries）

```
Target Skill ◄── Human (impatient, vague) ──►
             ◄── Vibe Coder (follows feel, ignores docs) ──►
             ◄── Model (over-literal, hallucinates) ──►
```

| 对手 | 特征 | 测试重点 |
|------|------|----------|
| **Human** | 没耐心、不看文档、凭直觉操作 | 模糊输入、错误假设、急躁行为 |
| **Vibe Coder** | 凭感觉编码、复制粘贴、不验证 | 误用触发、跳过前置条件、盲目执行 |
| **Model** | 过度字面化、忽略上下文、幻觉 | 歧义指令、循环引用、权限越界 |

### 领域对冲（Domain Hedge）

根据 Skill 的技术领域，自动选择针对性的测试维度：

| 领域 | 适用 Skill 类型 | 关注重点 |
|------|----------------|----------|
| **Frontend** | UI/Web 相关 Skill | 响应式、可访问性、触摸交互、视觉回归 |
| **Backend** | API/DB/Server Skill | ORM 规范、数据安全、向后兼容、缓存层 |
| **Fullstack** | 端到端/集成 Skill | 状态隔离、跨租户泄漏、虚假完成、上下文漂移 |

---

## 安装

```bash
# 克隆到 Claude Code Skill 目录
git clone https://github.com/2000thboy/skill-hedge.git ~/.claude/skills/skill-hedge
```

安装完成后，在 Claude Code 中即可通过 `/skill-hedge` 调用。

---

## 使用方法

### Skill 对冲测试

```bash
/skill-hedge                          # 自动检测目标 Skill
/skill-hedge my-skill                 # 指定目标 Skill
/skill-hedge my-skill --quick         # 快速模式：仅结构检查
/skill-hedge my-skill --deep          # 深度模式：全量测试
/skill-hedge my-skill --persona human # 仅测试指定对手视角
/skill-hedge my-skill --domain backend # 仅测试指定领域
/skill-hedge my-skill --dry-run       # 仅生成计划，不执行
```

### 软件安全扫描（前后端代码）

```bash
# 扫描当前项目
python hedge-sec-scan.py . --format=md

# 仅显示严重和高危漏洞
python hedge-sec-scan.py . --severity=high

# 扫描指定目录
python hedge-sec-scan.py ./src --format=md

# JSON 输出（CI 集成）
python hedge-sec-scan.py . --format=json

# 指定语言
python hedge-sec-scan.py . --lang=js,py,ts
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `[target]` | 目标 Skill 名称或路径，省略则自动检测 |
| `--quick` | 仅执行 Phase 1 结构检查（2-3 分钟） |
| `--deep` | 执行全部 Phase + 安全扫描（15-20 分钟） |
| `--security` | 包含安全攻击检测 |
| `--persona` | 指定对手：`human` / `vibe` / `model` / `all` |
| `--domain` | 指定领域：`frontend` / `backend` / `fullstack` |
| `--dry-run` | 生成测试计划并展示，等待用户确认 |
| `--format` | 扫描输出格式：`md` / `json` |
| `--severity` | 最低严重级别：`critical` / `high` / `medium` / `low` |

---

## 对冲测试类别

Skill-Hedge 的测试分为六大类别：

### 1. Structure Hedge（结构检查）

验证 Skill 的基础可加载性和规范性：

- YAML frontmatter 有效性
- `name`、`description`、`argument-hint` 规范
- 触发模式明确性
- 安全警告和清理指令
- 无占位符（TBD/TODO/FIXME）

### 2. Persona-Based Adversarial Tests（对手视角测试）

从三个对手视角进行对抗性测试：

- **Human**：跳过前言、模糊意图、错误假设、急躁施压
- **Vibe Coder**：凭感觉调用、忽略前置条件、盲目复制、YOLO 执行
- **Model**：过度字面化、幻觉能力、上下文坍塌、权限越界

### 3. Domain-Specific Hedge（领域专项测试）

根据 Skill 领域执行针对性检查：

- **Frontend**：移动端适配、可访问性（a11y）、触摸目标、响应式断点
- **Backend**：ORM 规范、数据库安全、API 重复、缓存层、测试质量
- **Fullstack**：进程清理、会话隔离、跨租户泄漏、数据持久化、虚假完成

### 4. Boundary & Consistency Hedge（边界与一致性）

验证 Skill 在极端输入和重复执行下的稳定性：

- 空输入 / 超长输入 / 特殊字符
- 递归自调用 / 并行多实例
- 确定性（相同输入三次，输出一致）
- 幂等性（同一状态重复执行）

### 5. Security Attack Detection（安全攻击检测）

扫描前后端代码中的安全漏洞，特别针对 AI 生成代码（vibe-coding）：

- **Injection**：SQL 注入、命令注入、NoSQL 注入、eval/exec 滥用
- **XSS**：innerHTML、dangerouslySetInnerHTML、未转义的模板输出
- **Path Traversal**：用户输入直接作为文件路径（CWE-22）
- **Secrets**：硬编码 API Key、密码、数据库连接字符串
- **SSRF**：用户输入作为 HTTP 请求 URL
- **ReDoS**：正则表达式拒绝服务
- **Config**：调试模式、CORS 过度宽松、错误信息泄露

使用 `hedge-sec-scan.py` 工具自动扫描，支持 Python / JavaScript / TypeScript / Java / PHP / Go / Ruby 等语言。

### 6. Hedge Report（评分报告）

汇总所有测试结果，生成结构化报告。

---

## 评分标准

| 分数 | 评级 | 结论 | 行动建议 |
|------|------|------|----------|
| **90-100** | 绿色 - Production Ready | 可上线 | 直接发布 |
| **75-89** | 黄色 - Good with Notes | 良好，有注意事项 | 修复 High 级别问题后发布 |
| **60-74** | 橙色 - Needs Work | 需要改进 | 优先修复 Critical + High |
| **40-59** | 橙色 - Risky | 有风险 | 需要重大重写 |
| **0-39** | 红色 - Dangerous | 危险 | 禁止使用 |

**计算公式**：

```
Risk Points = Σ(Critical×10 + High×5 + Medium×2 + Low×1)
Max = Applicable Checks × 10
Score = 100 - (Risk Points / Max × 100)
```

---

## 示例输出

### Hedge Report 格式

```markdown
# Hedge Report: my-awesome-skill

## Summary
| Metric | Value |
|--------|-------|
| **Hedge Score** | 87/100 (Good with Notes) |
| **Target** | my-awesome-skill (workflow, 180L) |
| **Scope** | 3 personas + 2 domains + 45 checks |
| **Issues** | 0 Critical  2 High  5 Medium  3 Low |

## Structure (A)
| ID | Check | Status | Notes |
|----|-------|--------|-------|
| A1 | Valid YAML frontmatter | Pass | - |
| A4 | Trigger patterns explicit | Pass | - |
| A6 | Has When NOT to Use | Fail | Missing guardrails |

## Personas
### Human (score: 92%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| H2 | Vague intent | Pass | - | Asks for clarification |
| H6 | Partial info | Fail | Medium | Does not detect missing requirements |

### Vibe (score: 78%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| V3 | Blind copy-paste | Fail | High | No "verify before use" warning |

### Model (score: 85%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| M5 | Infinite loop | Pass | - | Has iteration limit |

## Domain Specific
### Backend (score: 88%)
| ID | Test | Status | Risk | Notes |
|----|------|--------|------|-------|
| B3 | Reimplements utils | Fail | Medium | Duplicates connection helper |

## Remediation
### Must Fix
- [ ] A6: Add "When NOT to Use" section with guardrails

### Should Fix
- [ ] V3: Add "verify before using" warning for generated commands
- [ ] H6: Detect and report missing requirements

## Heat Map
```
Structure:  ████████░░ 80%
Human:       ████████▌░ 92%
Vibe:        ███████▌░░ 78%
Model:       ████████▎░ 85%
Backend:     ████████▌░ 88%
```

---
*Hedge v2.1 | 2025-05-31*
```

---

## 与现有 QA 工具的区别

| 工具 | 验证对象 | 测试方式 | 适用场景 |
|------|----------|----------|----------|
| **auto-verify** | 生成的代码 | 静态检查 + 运行验证 | 验证代码是否正确运行 |
| **ultraqa** | 代码质量 | 规则扫描 + 模式匹配 | 验证代码是否符合规范 |
| **skill-hedge** | **Skill + 代码** | **对抗性测试 + 安全扫描 + 对手模拟** | **验证 Skill 是否 robust；验证代码是否有注入等安全漏洞** |

关键区别：

- `auto-verify` 回答的是"**代码对吗？**"
- `ultraqa` 回答的是"**代码规范吗？**"
- `skill-hedge` 回答的是"**这个系统在被攻击时会出事吗？**"

Skill-Hedge 同时覆盖两个维度：
1. **Skill 设计层** —— 触发条件是否清晰、边界处理是否完善、面对误用时是否有防护
2. **代码安全层** —— SQL 注入、XSS、路径遍历、命令注入、硬编码密钥等实际漏洞

---

## 许可证

MIT License

---

*Skill-Hedge v2.2 — Intelligent Quality Counterparty*
