#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署 app.py 到 CN 面板主机, 重启服务并验证 /api/ports 端口展示功能。"""
import paramiko, datetime, json

KEY = "ssh_keys_backup/cn_id_ed25519.pem"
CN = {"host": "47.108.200.193", "port": 22022, "user": "root"}
LOCAL = "app.py"
REMOTE = "/opt/x-cfui/app.py"
API = "http://127.0.0.1:5000/aa888888/api/ports"
AUTH = ("admin", "aa888888")


def run():
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN["host"], port=CN["port"], username=CN["user"], pkey=key,
              timeout=25, look_for_keys=False, allow_agent=False)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    _, o, e = c.exec_command(
        f"cp -f {REMOTE} {REMOTE}.bak.{ts} 2>/dev/null; echo BACKUP_OK_{ts}", timeout=30)
    print("BACKUP:", o.read().decode(errors="replace").strip(), e.read().decode(errors="replace").strip())

    sftp = c.open_sftp()
    sftp.put(LOCAL, REMOTE)
    sftp.close()
    print("UPLOAD_DONE")

    _, o, e = c.exec_command(
        f"python3 -m py_compile {REMOTE} && echo COMPILE_OK || echo COMPILE_FAIL", timeout=40)
    print("COMPILE:", o.read().decode(errors="replace").strip(), e.read().decode(errors="replace").strip())

    _, o, e = c.exec_command("systemctl restart x-cfui; sleep 2; systemctl is-active x-cfui", timeout=40)
    print("SERVICE_ACTIVE:", o.read().decode(errors="replace").strip(), "ERR:", e.read().decode(errors="replace").strip())

    # 读取真实 admin 凭据用于鉴权验证
    _, o, e = c.exec_command(
        "python3 -c \"import json;s=json.load(open('/opt/x-cfui/state.json'));print(s.get('admin_user',''),'|',s.get('admin_pass',''))\"", timeout=20)
    line = o.read().decode(errors="replace").strip()
    print("DBG creds line:", repr(line))
    if "|" not in line or not line.split("|")[1].strip():
        print("WARN: 未能读取 admin 凭据, 跳过接口验证")
        c.close()
        return
    real_user, real_pass = [x.strip() for x in line.split("|", 1)]
    print("DBG user:", real_user, "pass_len:", len(real_pass))
    # 验证新接口: 拉取三台服务器端口
    _, o, e = c.exec_command(f"curl -s -u {real_user}:{real_pass} {API}", timeout=60)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    print("API_ERR:", err.strip())
    try:
        data = json.loads(out)
        if not data.get("ok"):
            print("API_OK=False:", data)
        else:
            for k, s in data.get("servers", {}).items():
                if not s.get("ok"):
                    print(f"  [{k}] 查询失败: {s.get('msg')}")
                    continue
                ports = s.get("ports", [])
                print(f"  [{k}] {s.get('name')} ({s.get('host')}) -> {len(ports)} 个监听端口")
                for p in ports:
                    print(f"        {p['proto']:>3} {p['addr']:<12} :{p['port']:<6} {p.get('proc','')}")
    except Exception as ex:
        print("API_PARSE_FAIL:", ex, "RAW:", out[:400])

    c.close()


if __name__ == "__main__":
    run()
