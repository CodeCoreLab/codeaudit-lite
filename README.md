# CodeAudit Lite

纯前端代码审计组件：把代码拖进浏览器，即刻得到 P0-P3 四级分级的质量与安全审计报告。

**零依赖 · 零后端 · 零上传** —— 代码全程在本地内存中分析，关闭页面即销毁，适配内网与合规敏感场景。

## 功能

- **多语言规则扫描**：37 条静态规则，覆盖 JS/TS、Python、Go、Java、SQL 与通用文本（JSON/YAML/Markdown/Shell 等）
- **凭据泄露检测**：云 AK/SK、数据库连接串、GitHub PAT、JWT、私钥块、Bearer 令牌，命中即 P0
- **注入类检测**：SQL 拼接、命令拼接、XSS（innerHTML / document.write）、动态执行（eval / new Function）
- **占位符智能去伪**：`<TOKEN>`、`${ENV_VAR}`、全大写蛇形占位不误报，让 P0 数量可信
- **健康评分**：加权扣分制（P0 -2.5 / P1 -1.5 / P2 -0.5 / P3 -0.1），2000 行基线归一化，1-10 分量化
- **分级过滤与检索**：严重度卡片点击过滤 + 关键词实时检索
- **Markdown 报告导出**：结论先行 + 指标表 + 分级明细，可直接贴进 PR / 周报

## 快速上手

1. 浏览器打开 `index.html`（无需安装、无需注册）
2. 把文件或文件夹拖进虚线区域（依赖目录与二进制自动跳过）
3. 读报告：有 P0 先停下修；无 P0 按分级排期；导出 Markdown 留档

### 引擎嵌入

`engine.js` 与 UI 完全解耦，可嵌入任意前端工程：

```html
<script src="engine.js"></script>
<script>
  const findings = CodeAudit.scanFile('config.yaml', fileText);
  // → [{ ruleId:'UNIV-03', severity:'P0', line:12, excerpt:'...', fix:'...' }]

  const score = CodeAudit.healthScore(findings, lineCount);
  // → 1..10 健康评分

  const rules = CodeAudit.RULES; // 37 条规则元数据，可按团队规范增删
</script>
```

CommonJS 环境同样可用：`const CodeAudit = require('./engine.js');`

## 页面结构

| 文件 | 说明 |
|------|------|
| `index.html` | 工具本体（上传 → 报告 → 规则库） |
| `intro.html` | 产品介绍（功能说明 / 核心特性 / 使用场景 / 快速上手） |
| `changelog.html` | 更新日志 |
| `engine.js` | 审计引擎（规则库 + 扫描 + 评分，双导出） |

## 严重度分级

| 级别 | 单条扣分 | 处置语义 |
|------|---------|---------|
| P0 阻断 | -2.5 | 可利用缺陷 / 凭据泄露 · 修复前禁止合入 |
| P1 严重 | -1.5 | 安全边界劣化 · 本迭代内修复 |
| P2 建议 | -0.5 | 质量隐患 · 排期优化 |
| P3 风格 | -0.1 | 风格卫生 · 顺手清理 |

总扣分按 2000 行基线归一化，得分 clamp 在 1-10。**≥8 绿**、6-7.9 黄、<6 红。

## 边界声明

静态规则扫描覆盖已知模式，**不能替代**人工深度审查、渗透测试与完整 SAST 流水线。P0 清零是合入底线，不是安全承诺。

## 隐私

基于浏览器 File API 本地分析：无网络请求、无后端、无遥测。请勿审计涉密代码——即便本地分析，合规红线同样适用。

## License

[MIT](LICENSE)
