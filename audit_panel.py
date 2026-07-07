#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
面板 app.py 自动化交叉审计:
 1) py_compile (Python 语法)
 2) 抽取内嵌 JS 做 node --check (JS 语法)
 3) i18n: HTML 中 data-i18n 用到的 key 必须存在于 zh/en 双字典; zh/en 键集合必须一致
 4) API: JS 中调用的 /api/* 必须在后端 do_GET/do_POST 有对应 handler
 5) DOM: JS 中 getElementById('X') 的 X 必须在 HTML 中存在 id="X"; 且 HTML 内 id 不重复
 6) 函数: HTML onclick="fn(" 的 fn 必须在 JS 中定义
 7) 结构: 每张 <div class="card"> 必须位于某个 <div class="section"> 内 (无孤儿卡片)
 8) 导航: 每个 .section 的 data-nav 必须有对应 nav 按钮
输出 PASS/FAIL 汇总, 任何 FAIL 视为 bug。
"""
import re, sys, subprocess, os, json, tempfile

APP = "C:/Users/qq123008/WorkBuddy/Claw/xray_admin/app.py"
NODE = "C:/Users/qq123008/.workbuddy/binaries/node/versions/22.22.2/node.exe"

problems = []   # (category, detail)
def fail(cat, detail): problems.append((cat, detail))
def ok(cat, n=0): pass

src = open(APP, encoding="utf-8").read()
lines = src.splitlines()

# ---- 1) py_compile ----
r = subprocess.run([sys.executable, "-m", "py_compile", APP], capture_output=True, text=True)
if r.returncode != 0:
    fail("PY_COMPILE", r.stderr.strip().splitlines()[-3:])
else:
    ok("PY_COMPILE")

# ---- 定位 PAGE 字符串区间 ----
m_start = src.find('PAGE = r"""')
assert m_start != -1, "PAGE not found"
# 找对应的结束 \"\"\"
end_marker = '"""'
seg = src[m_start:]
end_idx = seg.find('\n"""')
html = seg[:end_idx]  # 含 PAGE = r""" 前缀, 取 <!DOCTYPE 之后即可
doctype = html.find("<!DOCTYPE")
html = html[doctype:]
static_html = re.sub(r"<script>.*?</script>", "", html, flags=re.S)

# ---- 2) 抽取 JS 做 node --check ----
js_blocks = re.findall(r"<script>(.*?)</script>", html, re.S)
js = "\n".join(js_blocks)
with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tf:
    tf.write(js)
    jsfile = tf.name
if os.path.exists(NODE):
    rr = subprocess.run([NODE, "--check", jsfile], capture_output=True, text=True)
    if rr.returncode != 0:
        fail("JS_SYNTAX", rr.stderr.strip().splitlines()[-5:])
    else:
        ok("JS_SYNTAX")
else:
    fail("JS_SYNTAX", "node not found: " + NODE)
os.unlink(jsfile)

# ---- 3) i18n ----
data_i18n = set(re.findall(r'data-i18n="([^"]+)"', html))
# 解析 zh / en 字典 (嵌套于 const I18N = { zh:{...}, en:{...} })
def brace_block(text, start):
    depth = 0
    for off in range(start, len(text)):
        c = text[off]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:off+1]
    return text[start:]
def parse_i18n_sub(lang):
    i = src.find("const I18N = {")
    if i == -1: return None
    j = src.find("{", i)
    i18n_block = brace_block(src, j)
    m = re.search(r'\b%s\s*:\s*\{' % lang, i18n_block)
    if not m: return None
    sub = brace_block(i18n_block, m.end()-1)
    # 只匹配真实键: key 后紧跟引号值 (避免把字符串值里的 "Hint:" 误判为键)
    return set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*['\"]", sub))
zh = parse_i18n_sub("zh"); en = parse_i18n_sub("en")
if zh is None: fail("I18N", "zh dict not found")
if en is None: fail("I18N", "en dict not found")
if zh is not None and en is not None:
    for k in sorted(data_i18n):
        if k not in zh: fail("I18N_ZH_MISSING", "data-i18n=%s 不在 zh 字典" % k)
        if k not in en: fail("I18N_EN_MISSING", "data-i18n=%s 不在 en 字典" % k)
    only_zh = zh - en - data_i18n
    only_en = en - zh - data_i18n
    # 仅存在于字典但 HTML 没用到的 key 不算 bug, 但 zh/en 不对称算 bug
    asym = (zh - en) | (en - zh)
    for k in sorted(asym):
        fail("I18N_ASYMMETRIC", "key=%s 仅在 %s 字典中存在" % (k, "zh" if k in zh else "en"))

# ---- 4) API 调用 vs handler ----
# 后端 handler 路径
handlers = set()
for m in re.finditer(r'(?:ap|p)\s*==\s*"(/api/[^"]+)"', src):
    handlers.add(m.group(1))
# 也支持 startswith 形式
for m in re.finditer(r'(?:ap|p)\.startswith\("(/api/[^"]+)"\)', src):
    handlers.add(m.group(1) + "*")
# JS 中调用的 api 路径
api_calls = set()
for m in re.finditer(r"(?:api|fetch)\(\s*['\"`](/api/[^'\"`?\s]+)", js):
    api_calls.add(m.group(1))
# 处理模板字符串里 /api/...? 形式
for m in re.finditer(r"/api/[A-Za-z0-9_/]+", js):
    api_calls.add(m.group(0).rstrip("/"))
# 去掉可能的尾斜杠重复
for call in sorted(api_calls):
    base = call.split("?")[0]
    if base in handlers:
        continue
    # 允许前缀匹配 (startswith handler)
    matched = any(h.endswith("*") and base.startswith(h[:-1]) for h in handlers)
    if not matched and base not in handlers:
        fail("API_NO_HANDLER", "JS 调用 %s 无后端 handler (已知: %s)" % (base, sorted(handlers)))

# ---- 5) DOM id ----
html_ids = re.findall(r'\bid="([^"]+)"', static_html)
dup = set(x for x in html_ids if html_ids.count(x) > 1)
for d in sorted(dup):
    fail("DUP_ID", "HTML 中 id 重复: %s" % d)
used_ids = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]\s*\)", js))
for uid in sorted(used_ids):
    if uid not in html_ids:
        fail("ID_MISSING", "getElementById('%s') 在 HTML 无对应 id" % uid)

# ---- 6) onclick 函数定义 ----
onclicks = set(re.findall(r'onclick="([A-Za-z_][A-Za-z0-9_]*)\s*\(', html))
funcs = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", js))
funcs |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s+)?\(", js))
funcs |= set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function\s*\(", js))
for fn in sorted(onclicks):
    if fn not in funcs:
        fail("ONCLICK_UNDEF", "onclick=%s 未定义" % fn)

# ---- 7) section / card 嵌套 (孤儿卡片) ----
# 栈解析 div 标签, 追踪是否处于 section 内 (仅静态 HTML, 排除 script 内 JS 字符串)
tokens = list(re.finditer(r"<(/?div)([^>]*)>", static_html))
# 计算 static_html 在完整 src 中的行号偏移
base_line = src[:src.find(html[doctype:]) if False else src.find(static_html)].count("\n") + 1
stack = []  # True 表示 section, False 表示普通 div
orphan = []
for m in tokens:
    tag = m.group(1); attr = m.group(2)
    lineno = base_line + static_html[:m.start()].count("\n")
    if tag == "div":
        is_section = ('class="section' in attr) or ("class='section" in attr)
        is_card = ('class="card"' in attr) or ("class='card'" in attr)
        stack.append(is_section)
        if is_card and not any(stack):
            orphan.append((lineno, attr.strip()[:60]))
    else:
        if stack:
            stack.pop()
for ln, o in orphan:
    fail("ORPHAN_CARD", "L%d 存在不在任何 section 内的卡片: %s" % (ln, o))

# ---- 8) nav 按钮 vs section data-nav ----
def tags_with_data_nav(cls):
    out = set()
    for tag in re.findall(r"<[a-zA-Z]+[^>]*data-nav=\"([^\"]+)\"[^>]*>", static_html):
        out.add(tag)
    # 上面正则要求 data-nav 在前, 再补一个顺序无关的: 取所有带 data-nav 的标签, 判断是否含 cls
    for m in re.finditer(r"<([a-zA-Z]+)([^>]*)data-nav=\"([^\"]+)\"", static_html):
        if cls in m.group(2):
            out.add(m.group(3))
    for m in re.finditer(r"<([a-zA-Z]+)([^>]*)>", static_html):
        attrs = m.group(2)
        if cls in attrs and 'data-nav="' in attrs:
            nav = re.search(r'data-nav="([^"]+)"', attrs)
            if nav: out.add(nav.group(1))
    return out
nav_btns = tags_with_data_nav("navbtn")
section_navs = tags_with_data_nav("section")
for s in sorted(section_navs):
    if s not in nav_btns:
        fail("NAV_MISSING_SECTION", "section data-nav=%s 无对应 nav 按钮" % s)
for n in sorted(nav_btns):
    if n not in section_navs:
        fail("NAV_ORPHAN_BTN", "nav 按钮 data-nav=%s 无对应 section" % n)

# ---- 9) parse_qs 使用安全 (防 NameError 被 except 吞掉) ----
# 按函数切分, 每个含 parse_qs( 的函数必须在本函数内有 `from urllib.parse import parse_qs` 或 `urllib.parse.parse_qs`
func_spans = []
for m in re.finditer(r"\ndef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", src):
    start = m.start()
    # 找到下一个顶级 def 之前
    nxt = re.search(r"\ndef\s+", src[start+1:])
    end = nxt.start() + start + 1 if nxt else len(src)
    func_spans.append((m.group(1), src[start:end]))
for fname, body in func_spans:
    if "parse_qs(" in body:
        safe = ("from urllib.parse import parse_qs" in body) or ("urllib.parse.parse_qs" in body)
        if not safe:
            fail("PARSE_QS_UNSAFE", "函数 %s 使用 parse_qs 但无 import (有 NameError 被 except 吞掉风险)" % fname)

# ---- 10) 裸 except: (静默吞错, 可能掩盖 bug) ----
for m in re.finditer(r"except\s*:\s*(#|$)", src):
    ln = src[:m.start()].count("\n") + 1
    fail("BARE_EXCEPT", "L%d 裸 except: 会静默吞掉所有异常, 可能掩盖 bug" % ln)

# ---- 11) onchange 处理函数定义 ----
onchanges = set(re.findall(r'onchange="([A-Za-z_][A-Za-z0-9_]*)\s*\(', static_html))
for fn in sorted(onchanges):
    if fn not in funcs:
        fail("ONCHANGE_UNDEF", "onchange=%s 未定义" % fn)

# ---- 汇总 ----
print("=" * 60)
print("AUDIT REPORT for app.py")
print("=" * 60)
cats = {}
for c, d in problems:
    cats.setdefault(c, []).append(d)
if not problems:
    print("ALL CHECKS PASSED (no bug found)")
else:
    for c in sorted(cats):
        print("\n[%s] %d issue(s):" % (c, len(cats[c])))
        for d in cats[c][:40]:
            print("   - " + str(d))
    print("\nTOTAL: %d problem(s) across %d category(ies)" % (len(problems), len(cats)))
sys.exit(1 if problems else 0)
