import paramiko, json

CN = "47.108.200.193"
PORT = 22022
KEY = "ssh_keys_backup/cn_id_ed25519.pem"
AUTH = ("aa888888", "aa888888")
BASE = "http://127.0.0.1:5000/aa888888"

def ssh():
    k = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN, port=PORT, username="root", pkey=k, timeout=25, look_for_keys=False, allow_agent=False)
    return c

def curl(c, path, method="GET", body=None):
    if body is None:
        cmd = f"curl -s -m 30 -u aa888888:aa888888 {BASE}{path}"
    else:
        b = json.dumps(body).replace("'", "'\\''")
        cmd = f"curl -s -m 30 -u aa888888:aa888888 -X POST -H 'Content-Type: application/json' -d '{b}' {BASE}{path}"
    _, o, e = c.exec_command(cmd, timeout=60)
    return o.read().decode(errors="replace").strip()

c = ssh()
print("== GET before ==")
print(curl(c, "/api/routing_rules"))

print("\n== POST enable + tiktok rule + geoip sg ==")
r = curl(c, "/api/routing_rules", "POST", {
    "enabled": True,
    "rules": [
        {"type": "domain_suffix", "value": "tiktok.com", "outbound": "sg-out", "enabled": True},
        {"type": "geoip", "value": "sg", "outbound": "direct", "enabled": True},
    ],
})
print(r)

print("\n== live CN config routing ==")
_, o, _ = c.exec_command("cat /usr/local/etc/xray/config.json", timeout=30)
cfg = json.loads(o.read().decode())
print("domainStrategy:", cfg["routing"]["domainStrategy"])
for rule in cfg["routing"]["rules"]:
    print("  rule:", rule)
print("outbounds tags:", [x.get("tag") for x in cfg["outbounds"]])

_, o, _ = c.exec_command("systemctl is-active xray", timeout=20)
print("xray active:", o.read().decode().strip())

print("\n== POST disable (rollback) ==")
r2 = curl(c, "/api/routing_rules", "POST", {"enabled": False, "rules": []})
print(r2)
_, o, _ = c.exec_command("cat /usr/local/etc/xray/config.json", timeout=30)
cfg2 = json.loads(o.read().decode())
print("after-disable domainStrategy:", cfg2["routing"]["domainStrategy"])
print("after-disable rule count:", len(cfg2["routing"]["rules"]))
print("after-disable rules:", cfg2["routing"]["rules"])
c.close()
print("\nDONE")
