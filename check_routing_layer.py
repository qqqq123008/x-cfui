#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核查 CN xray 配置: 确认是否存在 iptables DNAT 端口转发, 以及 routing.rules 的层级(智能分流 vs 按端口分流)。"""
import paramiko

KEY = "ssh_keys_backup/cn_id_ed25519.pem"
CN = {"host": "47.108.200.193", "port": 22022, "user": "root"}

def run():
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN["host"], port=CN["port"], username=CN["user"], pkey=key,
              timeout=25, look_for_keys=False, allow_agent=False)

    def sh(cmd):
        _, o, e = c.exec_command(cmd, timeout=30)
        return o.read().decode(errors="replace").strip(), e.read().decode(errors="replace").strip()

    # 1) iptables DNAT 端口转发核查
    out, _ = sh("iptables -t nat -L -n 2>/dev/null | grep -iE 'DNAT|REDIRECT' || echo NO_IPTABLES_DNAT")
    print("=== iptables NAT (DNAT/REDIRECT) ===")
    print(out if out else "(empty)")

    # 2) xray 配置路径
    out, _ = sh("ls -1 /usr/local/etc/xray/config.json 2>/dev/null; ls -1 /etc/xray/config.json 2>/dev/null; echo '---service---'; cat /etc/systemd/system/xray.service 2>/dev/null | grep -i ExecStart")
    print("\n=== config path / service ===")
    print(out)

    # 3) routing.rules 层级 (提取 type/inboundTag/domain/ip/port/outboundTag)
    out, err = sh(r'''python3 - <<'PY'
import json
for p in ("/usr/local/etc/xray/config.json","/etc/xray/config.json"):
    try:
        cfg=json.load(open(p))
        break
    except Exception:
        cfg=None
if not cfg:
    print("NO_CONFIG")
else:
    rt=cfg.get("routing",{})
    print("domainStrategy:", rt.get("domainStrategy"))
    print("rule count:", len(rt.get("rules",[])))
    for i,r in enumerate(rt.get("rules",[])):
        parts=[]
        if "inboundTag" in r: parts.append("inboundTag="+json.dumps(r["inboundTag"]))
        if "domain" in r: parts.append("domain="+json.dumps(r["domain"]))
        if "ip" in r: parts.append("ip="+json.dumps(r["ip"]))
        if "port" in r: parts.append("port="+json.dumps(r["port"]))
        if "protocol" in r: parts.append("protocol="+json.dumps(r["protocol"]))
        print(f"  [{i}] {r.get('type')} {parts} -> {r.get('outboundTag')}")
    print("outbounds:", [o.get('tag') for o in cfg.get('outbounds',[])])
PY''')
    print("\n=== xray routing.rules ===")
    print(out)
    if err.strip():
        print("ERR:", err)
    c.close()

if __name__ == "__main__":
    run()
