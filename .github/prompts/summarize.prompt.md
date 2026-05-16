---
description: 压缩当前会话 — 提取决策/接口/待办，写入 session memory
---

把本次会话压缩为以下结构，并写入 `/memories/session/frideHide-<task>.md`：

```
## 目标
<一句话>

## 关键决策
- ...

## 涉及接口/符号
- file:line — 说明

## 已完成
- ...

## 待办
- [ ] ...

## 下次开新会话时应引用
#file:<path>  ...
```

写完后用一句话回复："压缩完毕，已存 <path>"。
