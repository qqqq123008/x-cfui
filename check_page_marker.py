import paramiko
cn = paramiko.SSHClient(); cn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cn.connect("47.108.200.193", port=22022, username="root",
           key_filename="ssh_keys_backup/cn_id_ed25519.pem", timeout=25,
           look_for_keys=False, allow_agent=False)
_, o, e = cn.exec_command(
    "curl -s -m 20 -u aa888888:aa888888 'http://127.0.0.1:5000/aa888888' | "
    "grep -o -e 'sshDownloadCurrent' -e '下载当前密钥' -e 'api/ssh_download_key' | sort -u",
    timeout=30)
print("page markers:", o.read().decode(errors="replace").strip().split("\n"))
cn.close()
