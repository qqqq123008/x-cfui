import paramiko
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("47.108.200.193", port=22022, username="root",
          key_filename="ssh_keys_backup/cn_id_ed25519.pem", timeout=25,
          look_for_keys=False, allow_agent=False)
_, o, e = c.exec_command("head -c 32 /usr/local/share/xray/geoip.dat | xxd | head -2; echo '---'; head -c 200 /usr/local/share/xray/geoip.dat | grep -a -o 'geoip' | head -1", timeout=20)
print(o.read().decode(errors="replace").strip())
print("ERR", e.read().decode(errors="replace").strip())
# validate by asking xray to load it (dry parse via xray geodata? simplest: check magic 0x67 0x65 0x6f)
_, o2, _ = c.exec_command("python3 -c \"d=open('/usr/local/share/xray/geoip.dat','rb').read(4); print('MAGIC', d)\" 2>/dev/null || echo no_py", timeout=20)
print(o2.read().decode(errors="replace").strip())
c.close()
