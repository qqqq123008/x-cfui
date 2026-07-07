#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证线上 x-cfui 面板: 服务状态 / 导航代码完整性 / 首页 HTML 渲染 / 运行日志。"""
import paramiko, json

KEY = "ssh_keys_backup/cn_id_ed25519.pem"
CN = {"host": "47.108.200.193", "port": 22022, "user": "root"}
REMOTE = "/opt/x-cfui/app.py"


def ssh_exec(c, cmd, timeout=40):
    _, o, e = c.exec_command(cmd, timeout=timeout)
    return o.read().decode(errors="replace"), e.read().decode(errors="replace")


def main():
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN["host"], port=CN["port"], username=CN["user"], pkey=key,
              timeout=25, look_for_keys=False, allow_agent=False)

    print("=== 1. 服务状态 ===")
    out, _ = ssh_exec(c, "systemctl is-active x-cfui")
    print("x-cfui active:", out.strip())

    print("\n=== 2. 线上 app.py 导航代码完整性 ===")
    out, _ = ssh_exec(c, f"grep -c 'class=\"navbtn' {REMOTE}; echo '---'; grep -c 'class=\"section' {REMOTE}; echo '---'; grep -c 'function switchNav' {REMOTE}; echo '---'; grep -c 'function initNav' {REMOTE}")
    print(out.strip())

    print("\n=== 3. 读取 admin 凭据并 curl 首页 HTML ===")
    out, _ = ssh_exec(c, "python3 -c \"import json;s=json.load(open('/opt/x-cfui/state.json'));print(s.get('admin_user',''),'|',s.get('admin_pass',''))\"")
    line = out.strip()
    if "|" not in line or not line.split("|")[1].strip():
        print("WARN: 无法读取凭据"); c.close(); return
    user, pwd = [x.strip() for x in line.split("|", 1)]
    out, err = ssh_exec(c, f"curl -s -u {user}:{pwd} http://127.0.0.1:5000/aa888888 -o /tmp/idx.html -w 'HTTP %{{http_code}}\\n'; echo '---navbtn count---'; grep -o 'class=\"navbtn' /tmp/idx.html | wc -l; echo '---section count---'; grep -o 'class=\"section' /tmp/idx.html | wc -l; echo '---switchNav calls---'; grep -o 'switchNav(' /tmp/idx.html | wc -l; echo '---initNav call---'; grep -o 'initNav();' /tmp/idx.html | wc -l")
    print(out.strip())
    if err.strip():
        print("curl err:", err.strip())

    print("\n=== 4. 运行日志 (最近 25 行) ===")
    out, _ = ssh_exec(c, "journalctl -u x-cfui -n 25 --no-pager 2>/dev/null | tail -25")
    print(out.strip() or "(无日志)")

    print("\n=== 5. 首页路由健壮性 (带/不带尾斜杠) + 接口健康检查 ===")
    for ep in ["", "/", "/api/ports", "/api/state"]:
        out, err = ssh_exec(c, f"curl -s -u {user}:{pwd} -o /dev/null -w '/aa888888{ep} -> HTTP %{{http_code}}\\n' http://127.0.0.1:5000/aa888888{ep}", timeout=60)
        print(out.strip() or err.strip())

    c.close()


if __name__ == "__main__":
    main()
