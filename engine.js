/* ================================================================
 * CodeAudit Lite · 前端代码审计引擎
 * ----------------------------------------------------------------
 * 零依赖纯前端，浏览器 File API 本地分析，代码不上传。
 * 流程：读文件 → 按扩展名规则扫描 → 占位符去伪 → P0-P3 分级 → 健康评分。
 * 规则覆盖 JS/TS / Python / Go / Java / SQL / 通用文本。
 * ================================================================ */
(function (global) {
  'use strict';

  /* ---------- 工具函数 ---------- */

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // 字符串内容替换为等长空格（保留结构，供"结构性"规则用）
  function stripStrings(line) {
    return line.replace(/(['"])((?:\\.|(?!\1).)*)\1/g, function (all) {
      return all.replace(/[^\s]/g, ' ');
    });
  }

  // 纯注释行判定
  function isCommentLine(line, lang) {
    var t = line.trim();
    if (!t) return false;
    if (lang === 'py') return t[0] === '#';
    if (lang === 'sql') return t[0] === '-' && t[1] === '-';
    if (lang === 'go' || lang === 'js') return t[0] === '/' && t[1] === '/';
    if (lang === 'java') return t[0] === '/' && t[1] === '/';
    // generic：# 或 // 或 <!-- 或 /* 开头
    return /^(?:#|\/\/|<!--|\/\*)/.test(t);
  }

  /* ---------- 规则库（P0-P3） ---------- */
  // secret: true → 必须在原始行匹配（凭据就在字符串里）
  // inCommentOk: true → 注释行也允许命中（如私钥头标记）
  var RULES = [
    /* ===== P0 · 阻断级 ===== */
    {
      id: 'UNIV-01', lang: 'generic', severity: 'P0', secret: true,
      title: '硬编码云凭据（AK/SK）',
      pattern: /(?:access[_-]?key[_-]?id|access[_-]?key|secret[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*['"][A-Za-z0-9/+]{16,}['"]/i,
      fix: '迁至环境变量或凭据管理服务；已入库的 key 视为已泄露必须轮换'
    },
    {
      id: 'UNIV-02', lang: 'generic', severity: 'P0', secret: true,
      title: '硬编码数据库连接串（含密码）',
      pattern: /(?:mongodb|mysql|postgres(?:ql)?|redis|amqp|mssql):\/\/[^\s'"\/]+:[^@\/\s]+@/i,
      fix: '连接串拆分到环境变量；密码部分严禁出现在源码中'
    },
    {
      id: 'UNIV-03', lang: 'generic', severity: 'P0', secret: true,
      title: 'API 令牌 / PAT 明文',
      pattern: /(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{35})/,
      fix: '迁至环境变量并立即轮换；令牌明文入库即泄露'
    },
    {
      id: 'UNIV-04', lang: 'generic', severity: 'P0', secret: true,
      title: 'Bearer 令牌 / 密码字段硬编码',
      pattern: /(?:Bearer\s+[A-Za-z0-9._-]{16,}|(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{3,}['"])/i,
      fix: '认证凭据经环境变量注入；日志与前端产物严禁携带'
    },
    {
      id: 'UNIV-05', lang: 'generic', severity: 'P0', inCommentOk: true,
      title: '私钥块标记',
      pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/,
      fix: '私钥不入库不入日志；已入库的密钥对全部作废重签'
    },
    {
      id: 'UNIV-06', lang: 'generic', severity: 'P0', secret: true,
      title: 'JWT 硬编码',
      pattern: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
      fix: 'JWT 是短期凭据，明文入库即泄露；改由登录流程动态获取'
    },
    {
      id: 'UNIV-07', lang: 'generic', severity: 'P0',
      title: 'SQL 注入（字符串拼接 SQL）',
      pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\s[^;\n]{0,80}?(?:\+\s*\w|\$\{|%\s*\w|%s\s*['"]|\+\s*['"])/i,
      fix: '参数化查询或 ORM；字符串拼 SQL 是注入主因'
    },
    {
      id: 'UNIV-08', lang: 'generic', severity: 'P0',
      title: '命令注入（拼接执行命令）',
      pattern: /(?:exec|spawn|execSync|system|shell_exec|os\.system)\s*\([^)]*(?:\+\s*\w|\$\{)/,
      fix: '固定命令白名单 + 参数数组传参；禁拼接执行'
    },
    {
      id: 'PY-01', lang: 'py', severity: 'P0',
      title: 'eval / exec 动态执行',
      pattern: /(?:^|[^.\w])(?:eval|exec)\s*\(/,
      fix: '改用显式解析（json.loads / ast.literal_eval）'
    },
    {
      id: 'PY-02', lang: 'py', severity: 'P0',
      title: 'pickle 反序列化不可信数据',
      pattern: /pickle\.loads?\s*\(/,
      fix: '改用 JSON；pickle 仅用于自产自销数据'
    },
    {
      id: 'PY-03', lang: 'py', severity: 'P0',
      title: 'requests 停用 SSL 校验',
      pattern: /verify\s*=\s*False/,
      fix: '内网自签证书走 truststore 而非关校验；禁 verify=False 上线'
    },
    {
      id: 'PY-04', lang: 'py', severity: 'P0',
      title: 'subprocess shell=True',
      pattern: /shell\s*=\s*True/,
      fix: '去掉 shell=True，参数列表化；必须 shell 时输入白名单'
    },
    {
      id: 'PY-05', lang: 'py', severity: 'P0',
      title: 'yaml.load 无 Loader',
      pattern: /yaml\.load\s*\((?![^)]*Loader)/,
      fix: 'yaml.safe_load；FullLoader 仍可执行部分对象'
    },
    {
      id: 'PY-06', lang: 'py', severity: 'P0',
      title: '裸 except: pass（吞异常）',
      pattern: /except\s*(?:Exception)?\s*:\s*$/,
      fix: '至少记录日志；全吞异常让故障静默'
    },
    {
      id: 'JS-01', lang: 'js', severity: 'P0',
      rawView: true, // 在原始行匹配（需检查右值是否字面量）
      title: 'innerHTML 插入动态内容（XSS）',
      pattern: /\.innerHTML\s*=\s*([^;\n]+)/,
      // 豁免：等号右侧是纯字符串字面量（可含 + 拼接的多个字面量）
      exempt: function (m) {
        var rhs = m[1].trim();
        return /^(['"`])(?:\\.|(?!\1).)*\1(\s*\+\s*\1(?:\\.|(?!\1).)*\1)*\s*$/.test(rhs);
      },
      fix: 'textContent 或消毒库；innerHTML = 纯字面量可豁免'
    },
    {
      id: 'JS-02', lang: 'js', severity: 'P0',
      title: 'document.write 动态写入',
      pattern: /document\.write\s*\(/,
      fix: 'DOM API 替代；document.write 阻塞解析且可注入'
    },
    {
      id: 'JS-03', lang: 'js', severity: 'P0',
      title: 'eval / new Function 动态执行',
      pattern: /(?:^|[^.\w])eval\s*\(|new\s+Function\s*\(/,
      fix: 'JSON.parse / 显式解析替代'
    },
    {
      id: 'JS-07', lang: 'js', severity: 'P0',
      title: 'postMessage 通配目标（*）',
      pattern: /postMessage\([^)]*,\s*['"]\*['"]\)/,
      fix: '指定 targetOrigin；通配可被恶意 iframe 接收'
    },

    /* ===== P1 · 严重级 ===== */
    {
      id: 'GO-01', lang: 'go', severity: 'P1',
      title: 'http.Client{} 无 Timeout',
      pattern: /http\.Client\{\s*\}/,
      fix: '设置 Timeout（如 30 * time.Second）；无超时=慢响应挂死 goroutine'
    },
    {
      id: 'GO-02', lang: 'go', severity: 'P1',
      title: 'I/O 错误被 `_ =` 忽略',
      pattern: /(?:^|\n)\s*_\s*[:=]?\s*=\s*(?:os\.)?(?:Create|Open|WriteFile|Remove|Mkdir)/,
      fix: '至少 log；忽略 I/O 错误导致静默数据丢失'
    },
    {
      id: 'JAV-01', lang: 'java', severity: 'P1',
      title: 'MD5 / SHA-1 摘要',
      pattern: /MessageDigest\.getInstance\(\s*["'](MD5|SHA-?1)["']\s*\)/i,
      fix: 'SHA-256 起步；MD5/SHA-1 已不满足安全强度'
    },
    {
      id: 'JAV-02', lang: 'java', severity: 'P1',
      title: 'java.util.Random 生成令牌/盐值',
      pattern: /new\s+Random\s*\(\s*\)/,
      fix: 'SecureRandom；Random 可预测'
    },
    {
      id: 'JAV-03', lang: 'java', severity: 'P1',
      title: '@RequestMapping 未限定 method',
      pattern: /@RequestMapping\s*\((?![^)]*method\s*=)/,
      fix: '显式限定 method=RequestMethod.GET/POST；否则全动词开放'
    },
    {
      id: 'JAV-04', lang: 'java', severity: 'P1',
      title: 'System.out 残留',
      pattern: /System\.out\.print/,
      fix: 'Logger；生产代码禁 System.out'
    },
    {
      id: 'SQL-01', lang: 'sql', severity: 'P0',
      title: 'GRANT ALL PRIVILEGES',
      pattern: /GRANT\s+ALL\s+PRIVILEGES/i,
      fix: '按最小权限授权；GRANT ALL 是运维捷径不是设计'
    },

    /* ===== P2 · 建议级 ===== */
    {
      id: 'PY-07', lang: 'py', severity: 'P2',
      title: '可变默认参数陷阱',
      pattern: /def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\})/,
      fix: '默认值用 None + 函数体内判空重建；[]/{} 跨调用共享'
    },
    {
      id: 'PY-08', lang: 'py', severity: 'P2',
      title: '== None / != None 比较',
      pattern: /==\s*None|!=\s*None/,
      fix: 'is None / is not None'
    },
    {
      id: 'PY-09', lang: 'py', severity: 'P2',
      title: '赋值型 open() 无 with',
      pattern: /(?:^|\n)\s*(?!\s*with\b)[\w.\[\]"']+\s*=\s*open\s*\(/,
      fix: 'with open(...) as f: 保证句柄释放'
    },
    {
      id: 'PY-10', lang: 'py', severity: 'P2',
      title: 'time.sleep ≥10s 轮询',
      pattern: /time\.sleep\(\s*(\d{2,})/,
      fix: '事件驱动/指数退避替代长 sleep；阻塞整个线程'
    },
    {
      id: 'JS-04', lang: 'js', severity: 'P2',
      title: 'localStorage 存敏感数据',
      pattern: /localStorage\.setItem\([^)]*(?:token|secret|password|key)/i,
      fix: '敏感数据走 HttpOnly Cookie；localStorage 可被 XSS 读取'
    },
    {
      id: 'JS-05', lang: 'js', severity: 'P2',
      title: 'console 输出敏感数据',
      pattern: /console\.(?:log|info|debug)\([^)]*(?:password|token|secret|apikey)/i,
      fix: '删调试残留；前端日志会进用户控制台'
    },
    {
      id: 'JS-06', lang: 'js', severity: 'P2',
      title: 'setTimeout 字符串参数',
      pattern: /setTimeout\s*\(\s*['"]/,
      fix: '传函数引用；字符串参数走隐式 eval'
    },
    {
      id: 'SQL-02', lang: 'sql', severity: 'P2',
      title: 'SELECT *',
      pattern: /SELECT\s+\*/i,
      fix: '显式列清单，隔离表结构变更影响'
    },

    /* ===== P3 · 风格级 ===== */
    {
      id: 'GEN-01', lang: 'generic', severity: 'P3',
      title: 'TODO / FIXME / HACK 残留',
      pattern: /\b(?:TODO|FIXME|XXX|HACK)\b[:\s]/,
      fix: '转 issue 跟踪；注释里的 TODO 无主无期',
      inCommentOk: true, // 仅注释行有意义
      commentOnly: true  // 标记：只在注释行生效
    },
    {
      id: 'GEN-02', lang: 'py', severity: 'P3',
      title: '裸 print 调试残留',
      pattern: /(?:^|\n)\s*print\s*\(/,
      fix: '改 logging；生产代码禁裸 print'
    },
    {
      id: 'GEN-03', lang: 'generic', severity: 'P3',
      title: 'Windows 盘符路径硬编码',
      pattern: /[A-Za-z]:\\[A-Za-z0-9_.\\-]+/,
      fix: '跨平台路径（os.path / pathlib / 相对路径）'
    },
    {
      id: 'GEN-04', lang: 'generic', severity: 'P3',
      title: 'HTTP（非 HTTPS）外链',
      pattern: /http:\/\/(?!localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[a-z0-9.-]+/i,
      fix: '统一 HTTPS'
    }
  ];

  /* ---------- 占位符去伪（secret 类规则专用） ---------- */
  var SECRET_IDS = {
    'UNIV-01': 1, 'UNIV-02': 1, 'UNIV-03': 1, 'UNIV-04': 1, 'UNIV-06': 1
  };

  function isPlaceholderValue(excerpt) {
    // 取 : = 后的值部分
    var m = excerpt.match(/[:=]\s*['"]?([^'"]*)['"]?\s*$/);
    var v = (excerpt.match(/Bearer\s+(\S+)/i) || [])[1] || (m ? m[1] : '');
    if (!v) return false;
    if (/^<[^>]+>$/.test(v)) return true;            // <PLACEHOLDER>
    if (/^\$\{[^}]+\}$/.test(v)) return true;        // ${ENV_VAR}
    if (/^[A-Z][A-Z0-9_]{5,}$/.test(v)) return true; // 全大写蛇形
    if (/^(?:your|xxx|dummy|sample|example)[-_]/i.test(v)) return true;
    if (/^(\.\.\.|…)/.test(v)) return true;
    return false;
  }

  /* ---------- 语言识别（按扩展名） ---------- */
  var EXT_LANG = {
    js: 'js', mjs: 'js', cjs: 'js', jsx: 'js', ts: 'js', tsx: 'js',
    py: 'py', pyw: 'py',
    go: 'go', java: 'java',
    sql: 'sql',
    json: 'generic', yml: 'generic', yaml: 'generic', toml: 'generic',
    ini: 'generic', conf: 'generic', env: 'generic', md: 'generic',
    txt: 'generic', sh: 'generic', bat: 'generic', ps1: 'generic',
    htm: 'generic', html: 'generic', css: 'generic'
  };

  function detectLang(name) {
    var ext = (name.split('.').pop() || '').toLowerCase();
    return EXT_LANG[ext] || 'generic';
  }

  /* ---------- 单文件扫描 ---------- */
  function scanFile(name, src) {
    var langKey = detectLang(name);
    var rules = RULES.filter(function (r) {
      return r.lang === langKey || r.lang === 'generic';
    });

    var findings = [];
    var lines = src.split('\n');

    lines.forEach(function (line, i) {
      if (!line) return;
      var inComment = isCommentLine(line, langKey);
      var rawLine = line;
      var cleaned = stripStrings(line);

      for (var k = 0; k < rules.length; k++) {
        var r = rules[k];
        if (inComment && !r.inCommentOk) continue;
        if (r.commentOnly && !inComment) continue;
        var m = r.pattern.exec((r.secret || r.rawView) ? rawLine : cleaned);
        if (!m && r.secret) m = r.pattern.exec(cleaned); // 双视图兜底
        if (!m) continue;
        if (r.exempt && r.exempt(m)) continue;           // 规则级豁免
        if (r.secret && isPlaceholderValue(m[0])) continue; // 占位符去伪
        findings.push({
          ruleId: r.id, severity: r.severity, title: r.title, fix: r.fix,
          file: name, line: i + 1,
          excerpt: m[0].slice(0, 90),
          raw: line.trim().slice(0, 140)
        });
      }
    });
    return findings;
  }

  /* ---------- 健康评分 ---------- */
  // 加权扣分制，2000 行基线归一化，保底 1 分
  var SEV_WEIGHT = { P0: 2.5, P1: 1.5, P2: 0.5, P3: 0.1 };

  function healthScore(findings, loc) {
    var w = { P0: 0, P1: 0, P2: 0, P3: 0 };
    findings.forEach(function (f) { w[f.severity]++; });
    var penalty = w.P0 * 2.5 + w.P1 * 1.5 + w.P2 * 0.5 + w.P3 * 0.1;
    var norm = Math.max(1, (loc || 0) / 2000);
    var score = 10 - penalty / norm;
    return Math.max(1, Math.min(10, Math.round(score * 10) / 10));
  }

  /* ---------- 导出 ---------- */
  var api = {
    scanFile: scanFile,
    healthScore: healthScore,
    RULES: RULES,
    esc: esc,
    detectLang: detectLang,
    SEV_WEIGHT: SEV_WEIGHT
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  global.CodeAudit = api;

})(typeof window !== 'undefined' ? window : this);
