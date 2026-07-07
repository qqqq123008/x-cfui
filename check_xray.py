import paramiko
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("47.108.200.193", port=22022, username="root",
          key_filename="ssh_keys_backup/cn_id_ed25519.pem", timeout=25,
          look_for_keys=False, allow_agent=False)
for cmd in ["systemctl is-active xray",
            "ls -la /usr/local/share/xray/ 2>/dev/null | grep -i geo || echo NO_GEO_SHARE",
            "ls -la /usr/local/etc/xray/ 2>/dev/null | grep -i geo || echo NO_GEO_ETC",
            "systemctl status xray --no-pager -l 2>/dev/null | tail -6"]:
    _, o, e = c.exec_command(cmd, timeout=30)
    print(">>>", cmd)
    print(o.read().decode(errors="replace").strip())
    err = e.read().decode(errors="replace").strip()
    if err:
        print("ERR", err)
c.close()
