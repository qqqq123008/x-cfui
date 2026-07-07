import paramiko, json

CN = "47.108.200.193"; PORT = 22022
KEY = "ssh_keys_backup/cn_id_ed25519.pem"
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

def xactive(c):
    _, o, _ = c.exec_command("systemctl is-active xray", timeout=20)
    return o.read().decode().strip()

c = ssh()
print("== GET before ==", json.loads(curl(c, "/api/routing_rules"))["geoip_available"], "(geoip_available)")

print("\n== A) POST domain rule tiktok.com -> sg-out ==")
r = json.loads(curl(c, "/api/routing_rules", "POST", {"enabled": True, "rules": [
    {"type": "domain_suffix", "value": "tiktok.com", "outbound": "sg-out", "enabled": True}]}))
print("ok:", r["ok"], "| msg:", r["msg"])
print("xray active after A:", xactive(c))

_, o, _ = c.exec_command("cat /usr/local/etc/xray/config.json", timeout=30)
cfg = json.loads(o.read().decode())
print("domainStrategy:", cfg["routing"]["domainStrategy"])
print("rules[0..1]:", cfg["routing"]["rules"][:2])

print("\n== B) POST geoip rule (should be REJECTED, dat missing) ==")
r2 = json.loads(curl(c, "/api/routing_rules", "POST", {"enabled": True, "rules": [
    {"type": "geoip", "value": "sg", "outbound": "direct", "enabled": True}]}))
print("ok:", r2["ok"], "| msg:", r2["msg"])
print("xray active after B:", xactive(c), "(must still be active)")

print("\n== C) Disable (rollback to clean) ==")
r3 = json.loads(curl(c, "/api/routing_rules", "POST", {"enabled": False, "rules": []}))
print("ok:", r3["ok"], "| msg:", r3["msg"])
print("xray active after C:", xactive(c))
_, o, _ = c.exec_command("cat /usr/local/etc/xray/config.json", timeout=30)
cfg3 = json.loads(o.read().decode())
print("final domainStrategy:", cfg3["routing"]["domainStrategy"], "| rule count:", len(cfg3["routing"]["rules"]))
c.close()
print("\nALL CHECKS DONE")
