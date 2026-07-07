#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 CN 面板修复: 用 real app.py 函数(走 PANEL_KEY)核验三台 exit 的开机自启/BBR/防火墙。"""
import paramiko

KEY = "ssh_keys_backup/cn_id_ed25519.pem"
CN = {"host": "47.108.200.193", "port": 22022, "user": "root"}

REMOTE_PY = r'''
import app
st = app.load_state()
print("PANEL_KEY_EXISTS=", __import__("os").path.exists(app.PANEL_KEY))
for ex in st["exits"]:
    a = app.autostart_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22))
    b = app.bbr_status_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22))
    f = app.fw_status_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22))
    print("== %s (%s:%s) ==" % (ex["name"], ex["address"], ex.get("ssh_port",22)))
    print("  autostart.ok=", a.get("ok"), a.get("msg",""), "| xray_active=", a.get("xray_active"), "| bbr_active=", a.get("bbr_active"), "| fw_enabled=", a.get("firewall_enabled"))
    print("  bbr.ok=", b.get("ok"), b.get("msg",""), "| cca=", b.get("cca"))
    print("  fw.ok=", f.get("ok"), f.get("msg",""), "| firewall=", f.get("firewall"))
'''

def run():
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN["host"], port=CN["port"], username=CN["user"], pkey=key,
              timeout=25, look_for_keys=False, allow_agent=False)
    _, o, e = c.exec_command("cd /opt/x-cfui && python3 - " + "<<'PYEOF'\n" + REMOTE_PY + "\nPYEOF", timeout=120)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    print(out)
    if err.strip():
        print("STDERR:", err)
    c.close()

if __name__ == "__main__":
    run()
