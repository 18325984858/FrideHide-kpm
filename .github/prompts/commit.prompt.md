---
description: 根据 #changes 生成 Conventional Commits 提交信息
mode: ask
---

基于当前 `#changes` 生成提交信息：

- **标题**：`<type>(<scope>): <desc>`，≤ 60 字
  - `type` ∈ feat / fix / refactor / perf / build / chore / docs / test
  - `scope` 用目录名（kpms / tools / kernel / user）
- **正文**：
  - What：1-3 行说改了什么
  - Why：1-2 行说为什么
  - 不要写 How
- **footer**（如有）：
  - `BREAKING CHANGE: <impact>` 当 supercall.h 或 KPM ABI 变更
  - `Refs: #<issue>`

输出纯文本，不要 markdown 围栏。
