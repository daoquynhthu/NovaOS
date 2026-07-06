# AGENT.md — NovaOS 代理行为宪法

> **定位**: 本仓库中代理的最高行为规范，不可违反。  
> **优先级**: 高于一切其他文档。如果其他文档与本文件冲突，以本文件为准。  
> **适用范围**: 任何在仓库中执行代码修改、文档撰写、审计、规划的代理。

---

## 1. 文档体系与引用关系

```
AGENT.md (行为宪法，最高约束)
  ├── 引用 ──▶ PLAN.md (宏观路线图)
  ├── 引用 ──▶ TASK.md (动态执行计划)
  ├── 引用 ──▶ ISSUE.md (已知问题归档)
  ├── 引用 ──▶ PROGRESS.md (进度摘要)
  ├── 引用 ──▶ INDEX.md (代码索引)
  │
  └── 引用 ──▶ docs/*.md (稳定架构文档)
       ARCH-NOVAOS-PROPOSAL-001     — 项目愿景与架构原则
       ARCH-SYSCALL-DESIGN-001      — Syscall 接口设计
       ARCH-VERIFICATION-SPEC-001   — 验证规范
       ARCH-MEMORY-ERROR-SPEC-001   — 内存错误规范
```

**文档间引用规则**:
- PLAN.md 引用架构文档时使用 `[ARCH-NOVAOS-PROPOSAL-001]` 格式
- TASK.md 引用 PLAN.md 的阶段编号如 `[PLAN-P1]`
- ISSUE.md 每一项引用 TASK.md 的子任务编号如 `[TASK-3.2]`
- PROGRESS.md 引用 ISSUE.md 或 TASK.md 的完成项
- INDEX.md 是唯一代码真相源，AGENT 工作前必须先读 INDEX.md

## 2. 核心工作流（8 步闭环）

```
Step 1: 阅读 PLAN.md → 确认当前阶段
Step 2: 草拟 TASK.md → 拆分子任务；功能性代码子任务先写 RED test（预期失败）
Step 3: 开始实现 → 使 RED test 变为 GREEN（仅功能性代码）
Step 4: TASK.md 全部完成后 → 启动独立子Agent 审计 diff → 产出写入 ISSUE.md
Step 5: 修复 ISSUE.md 中所有项
Step 6: 再次审计（回到 Step 4），直到零 ISSUE
Step 7: 更新 INDEX.md 相应条目 + 新增 PROGRESS.md 项 + 清空 TASK.md
Step 8: 进入 PLAN 下一阶段
```

## 3. RED/GREEN 测试规则

**适用范围**：
RED/GREEN 机制**仅适用于功能性代码变更**（新增/修改行为、新增测试、修复 bug 等）。
不适用于：纯文档调整、路线规划、Issue 归档、格式清理、文件移动等无运行时语义变化的变更。

**定义**：
- RED：测试预期失败（功能未实现时编译不应通过，或运行不应通过）
- GREEN：实现代码完成后测试应通过

**执行规则**：
1. 功能性子任务必须先有 RED test，提交到仓库中，确认其确实失败
2. 然后开始编写实现代码
3. 实现完成后运行同一个测试，确认变 GREEN
4. RED→GREEN 是原子操作：不允许提交"只有 RED 没有 GREEN"的代码
5. 如果 RED 没有失败（即功能意外已存在），则该子任务无效，重新定义
6. 如果 GREEN 不通过，迭代修改直到通过，否则不准推进

**测试类型**（按优先级）：
- `cargo check --workspace` — 最低门禁
- `cargo build --workspace --release` — 完整编译
- `NOVA_TEST_TIMEOUT_SECONDS=120 ./test.ps1` — QEMU 集成回归
- 新增单元测试 — 随 TASK 定义

## 4. 负向约束（禁止行为）

1. **禁止同时提交功能 + 重构 + 日志清理**。单次变更只能有一个意图。
2. **禁止一次性删除回退路径**。任何服务化迁移必须保留 fallback，直到回归稳定。
3. **禁止修改架构文档（`docs/*.md`）中的 ARCH-ID 和核心语义**。架构文档只能添加修订附录（`## 修订记录`），不能重写正文。
4. **禁止跳过审计**。Step 4 的独立子Agent 审计是强制性的，不得由实现者自行替代。
5. **禁止在 PROGRESS.md 中写"打算做什么"**。PROGRESS.md 只用过去时记录已完成事实。
6. **禁止用延长测试超时掩盖不稳定**。门禁超时是团队约束，不是调试参数。
7. **禁止修改 `.gitignore` 中已有的安全相关条目**（如 `.env`）。
8. **禁止在未阅读 INDEX.md 的情况下修改代码**。

## 5. 审计规范

**普通审计**（Step 4，TASK.md 全部完成后）：
- 由独立子 Agent 执行，审计当前 TASK.md 涉及的全部 diff
- 检查：语义正确性、测试覆盖、文档一致性、负向约束遵守
- 产出：ISSUE.md 条目
- 修复所有 ISSUE 后再次审计，直到零 ISSUE，方可清空 TASK.md

**高规格并行审计**（重要里程碑或 PLAN 阶段结束时）：
- 启动多个独立子 Agent 并行审计
- 检查范围扩大：架构一致性、安全性、性能退化、回归覆盖盲区
- 每个审计 Agent 独立产出 ISSUE 列表，汇总去重
- 所有 ISSUE 必须修复并通过再审计，才能进入下一阶段

## 6. 文档维护规则

| 文档 | 谁维护 | 何时更新 |
|------|--------|---------|
| AGENT.md | 仓库维护者（非代理） | 行为规则变更时 |
| PLAN.md | 仓库维护者 | 路线变更时 |
| TASK.md | 当前执行代理 | 每次工作开始时拆解，完成时标记 |
| ISSUE.md | 审计代理 | 每次审计后追加，修复后关闭 |
| PROGRESS.md | 执行代理 | 每个子任务完成后 |
| INDEX.md | 执行代理 | 每次代码变更后更新相关条目 |
| docs/*.md | 仓库维护者 | 架构变更时追加修订附录 |

## 7. 启动工作流默认入口

首次进入仓库时，默认执行：
1. 读取本文件（AGENT.md）
2. 读取 INDEX.md
3. 读取 PLAN.md
4. 读取 PROGRESS.md
5. 读取 ISSUE.md（了解当前已知问题）
6. 如果 TASK.md 非空且当前阶段有未完成项 → 继续执行
7. 如果 TASK.md 为空 → 从 PLAN.md 确认下一阶段 → 草拟 TASK.md
