/**
 * CodeAudit Lite 回归测试（零依赖，node tests/regression.test.js 直接跑）
 *
 * 覆盖的历史缺陷：
 * - 占位符去伪把真实 AWS Access Key 判为占位符 → UNIV-01（P0）对 AWS 凭据系统性漏报
 *
 * 用法：node tests/regression.test.js
 */
'use strict';

const path = require('path');
const CodeAudit = require(path.join(__dirname, '..', 'engine.js'));

let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log('PASS  ' + name);
  } else {
    failed++;
    console.log('FAIL  ' + name + (detail ? '  → ' + detail : ''));
  }
}

/** 扫描一段文本，返回命中的规则 id 集合（scanFile(name, src) 直接返回 findings 数组） */
function ruleIds(code, filename) {
  const findings = CodeAudit.scanFile(filename || 'test.js', code) || [];
  return findings.map(function (f) { return f.ruleId; });
}

/* ---------- AWS Access Key 必须命中 UNIV-01 ---------- */

const awsKeys = [
  'AKIAQYLPMN5HHHFPZAM2',   // 真实格式
  'AKIAIOSFODNN7EXAMPLE',    // AWS 官方示例格式
  'AKIAZZZZZZZZZZZZZZZZ',
  'ASIAQYLPMN5HHHFPZAM2'    // 临时凭据前缀
];

awsKeys.forEach(function (k) {
  const ids = ruleIds('const aws_access_key_id = "' + k + '";');
  check(
    'AWS AK 必须命中 UNIV-01: ' + k,
    ids.indexOf('UNIV-01') !== -1,
    '实际命中: ' + JSON.stringify(ids)
  );
});

/* ---------- 真正的占位符仍应被跳过（不能矫枉过正） ---------- */

const placeholders = [
  'const MY_CONSTANT_NAME = "SOME_VALUE";',
  'const DB_PASSWORD_CONST = "CHANGE_ME";',
  'const api_key = "your_api_key_here";',
  'const api_key = "<PLACEHOLDER>";',
  'const api_key = "${API_KEY}";'
];

placeholders.forEach(function (code) {
  const ids = ruleIds(code);
  check(
    '占位符不应误报: ' + code.slice(0, 46),
    ids.indexOf('UNIV-01') === -1,
    '实际命中: ' + JSON.stringify(ids)
  );
});

/* ---------- 结果结构基本健全 ---------- */

check('scanFile 返回 findings 数组', Array.isArray(CodeAudit.scanFile('test.js', 'var a = 1;')));
check('scanFile 返回规则元数据', Array.isArray(CodeAudit.RULES) && CodeAudit.RULES.length > 0);

/* ---------- 汇总 ---------- */
console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
