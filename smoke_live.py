#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真机运行时冒烟测试: 连 CN, 用本机面板进程核验关键接口无 500。
注意: 面板 API 挂在 /{token}/api/... 下, BASE 由前端 location.pathname 推导。"""
import paramiko, json, sys, re

CN = "47.108.200.193"; PORT = 22022
KEY = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/ssh_keys_backup/cn_id_ed25519.pem"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(CN, port=PORT, username="root", key_filename=KEY, timeout=15)
print("[connect] CN OK")

_, out, _ = ssh.exec_command("cat /opt/x-cfui/state.json")
state = json.loads(out.read().decode("utf-8"))
user = state["admin_user"]; pw = state["admin_pass"]; tok = state.get("entry_token", "aa888888")
print("[creds] user=%s token=%s" % (user, tok))

BASE = "http://127.0.0.1:5000/%s" % tok
auth = "-u %s:%s" % (user, pw)

def run(cmd):
    _, out, err = ssh.exec_command(cmd)
    return out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")

def parse(resp):
    # resp 含响应头 + 空行 + body
    m = re.search(r"HTTP/\d\.\d+\s+(\d+)", resp)
    code = m.group(1) if m else "?"
    parts = resp.split("\r\n\r\n", 1)
    if len(parts) == 2:
        body = parts[1]
    else:
        body = resp
    return code, body

# 页面
resp, _ = run("curl -s -i %s http://127.0.0.1:5000/%s" % (auth, tok))
code, _ = parse(resp)
print("[page] /%s -> HTTP %s" % (tok, code))

tests = [
    ("GET", "/api/state", None),
    ("GET", "/api/brute_get", None),
    ("GET", "/api/backup/list", None),
    ("GET", "/api/backup/export", None),
    ("GET", "/api/routing_rules", None),
    ("GET", "/api/machine_backup/list?target=cn", None),
    ("GET", "/api/firewall?target=cn", None),
    ("GET", "/api/ssh_status?target=cn", None),
    ("GET", "/api/ports", None),
    ("POST", "/api/brute_set", '{"window":60,"max":17,"ban":17200}'),
]
fails = []
for method, path, payload in tests:
    if method == "GET":
        cmd = "curl -s -i %s %s%s" % (auth, BASE, path)
    else:
        cmd = ("curl -s -i -X POST %s %s%s -H Content-Type:application/json "
               "-d '%s'") % (auth, BASE, path, payload)
    resp, _ = run(cmd)
    code, body = parse(resp)
    ok_json = False; is_ok = None
    try:
        j = json.loads(body); ok_json = True; is_ok = j.get("ok")
    except Exception:
        ok_json = False
    status = "OK" if (code == "200" and ok_json) else "FAIL"
    if status == "FAIL":
        fails.append((method, path, code, ok_json, body[:200]))
    print("[%s] %-6s %-42s HTTP=%s json=%s ok=%s" % (status, method, path, code, ok_json, is_ok))

# 路径穿越防护: 应被 400 拒绝
resp, _ = run("curl -s -i %s '%s/api/backup/download?file=../../etc/passwd'" % (auth, BASE))
code, body = parse(resp)
print("[GUARD] path-traversal download -> HTTP=%s (期望 400)" % code)
if code != "400":
    fails.append(("GET", "/api/backup/download?file=../../etc/passwd", code, False, "traversal not blocked"))

# 删除保护: default_backup.json 不可删
resp, _ = run(("curl -s -i -X POST %s '%s/api/backup/delete' "
               "-H Content-Type:application/json -d '{\"file\":\"default_backup.json\"}'") % (auth, BASE))
code, body = parse(resp)
print("[GUARD] delete protected file -> HTTP=%s body=%s (期望拒绝)" % (code, body[:120]))
try:
    if json.loads(body).get("ok") is True:
        fails.append(("POST", "/api/backup/delete default_backup", code, True, "should be blocked"))
except Exception:
    pass

# 备份下载非法文件名 (file 带 /)
resp, _ = run("curl -s -i %s '%s/api/backup/download?file=..%%2f..%%2fetc%%2fpasswd'" % (auth, BASE))
code, _ = parse(resp)
print("[GUARD] url-encoded traversal -> HTTP=%s (期望 400)" % code)
if code != "400":
    fails.append(("GET", "encoded traversal", code, False, "not blocked"))

ssh.close()
print("\n==== SMOKE RESULT ====")
if not fails:
    print("ALL RUNTIME SMOKE TESTS PASSED (no bug found)")
    sys.exit(0)
else:
    print("FOUND %d FAILURE(S):" % len(fails))
    for f in fails:
        print("  ", f)
    sys.exit(1)
