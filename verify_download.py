import paramiko, json, tempfile, os

cn = paramiko.SSHClient(); cn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cn.connect("47.108.200.193", port=22022, username="root",
           key_filename="ssh_keys_backup/cn_id_ed25519.pem", timeout=25,
           look_for_keys=False, allow_agent=False)

hosts = {"cn": ("47.108.200.193", 22022),
         "sg": ("43.156.107.54", 23022),
         "ru": ("193.53.126.80", 24022)}

def tmp_key(priv):
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "w") as f:
        f.write(priv + "\n")
    os.chmod(path, 0o600)
    return path

print("=== 1) panel download endpoint ===")
privs = {}
for tgt in ("cn", "sg", "ru"):
    _, o, e = cn.exec_command(
        "curl -s -m 20 -u aa888888:aa888888 "
        "'http://127.0.0.1:5000/aa888888/api/ssh_download_key?target=%s'" % tgt, timeout=40)
    try:
        r = json.loads(o.read().decode(errors="replace"))
    except Exception as ex:
        print("  %s: PARSE FAIL %s" % (tgt, ex)); continue
    print("  %s: ok=%s name=%s" % (tgt, r.get("ok"), r.get("name")))
    if r.get("ok"):
        privs[tgt] = r["priv"]

print("\n=== 2) returned key logs into its server ===")
for tgt, (ip, port) in hosts.items():
    if tgt not in privs:
        print("  %s: SKIP (no key)" % tgt); continue
    p = tmp_key(privs[tgt])
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, port=port, username="root", key_filename=p, timeout=20,
                  look_for_keys=False, allow_agent=False)
        _, o, e = c.exec_command("echo LOGIN_OK", timeout=20)
        print("  %s: %s" % (tgt, o.read().decode().strip()))
    except Exception as ex:
        print("  %s: LOGIN FAIL %s" % (tgt, ex))
    finally:
        c.close(); os.remove(p)

print("\n=== 3) returned pub matches authorized_keys on server ===")
for tgt, (ip, port) in hosts.items():
    if tgt not in privs:
        continue
    p = tmp_key(privs[tgt])
    k = paramiko.Ed25519Key.from_private_key_file(p)
    pub = k.get_name() + " " + k.get_base64()
    os.remove(p)
    p2 = tmp_key(privs[tgt])
    ck2 = paramiko.SSHClient(); ck2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ck2.connect(ip, port=port, username="root", key_filename=p2, timeout=20,
                    look_for_keys=False, allow_agent=False)
        _, o, e = ck2.exec_command("grep -c '%s' /root/.ssh/authorized_keys" % pub, timeout=20)
        print("  %s: pub in authorized_keys count=%s" % (tgt, o.read().decode().strip()))
    except Exception as ex:
        print("  %s: check FAIL %s" % (tgt, ex))
    finally:
        ck2.close(); os.remove(p2)

cn.close()
