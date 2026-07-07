#!/usr/bin/env python3
import paramiko, os, time

KEY = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/ssh_keys_backup/cn_id_ed25519.pem"
HOST, PORT, USER = "47.108.200.193", 22022, "root"
LOCAL_DIR = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=PORT, username=USER, key_filename=KEY, timeout=15)
print("SSH CONNECTED ->", HOST)

sftp = ssh.open_sftp()
for f in ["backup_xcfui.sh", "xcfui.sh"]:
    sftp.put(os.path.join(LOCAL_DIR, f), f"/root/{f}")
print("uploaded backup_xcfui.sh, xcfui.sh")

def run(cmd, timeout=120):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return out, err, stdout.channel.recv_exit_status()

print("\n===== [1] 实时备份 (真实执行, 只读+写/root) =====")
out, err, rc = run("bash /root/backup_xcfui.sh 2>&1 | tail -20")
print(out)
if rc != 0:
    print("[backup rc]", rc, err[-500:])
    # 备份脚本可能返回非0, 看产物是否存在
out2, _, _ = run("ls -lh /root/xcfui_backup_*.tar.gz 2>/dev/null | tail -1")
print("产物:", out2.strip())

latest, _, _ = run("ls -t /root/xcfui_backup_*.tar.gz 2>/dev/null | head -1")
latest = latest.strip()
print("最新包:", latest)

print("\n===== [2] 备份成员清单核对 =====")
out, _, _ = run(f"tar -tzf {latest} | wc -l")
print("成员总数:", out.strip())
for needle in ["opt/x-cfui/state.json","opt/x-cfui/app.py","opt/x-cfui/ssh_keys","opt/x-cfui/host_keys",
               "usr/local/etc/xray/config.json","etc/ssh/ssh_host_","fail2ban","sysctl.d","xray.service",
               "x-cfui.service","nginx","var/www/html","nftables","MANIFEST.txt","restore_xcfui.sh"]:
    o,_,_ = run(f"tar -tzf {latest} | grep -c '{needle}'")
    print(f"  [{'OK' if o.strip() not in ('0','') and int(o.strip() or 0)>0 else 'MISS'}] {needle}: {o.strip()}")
# 确认不含系统文件
o,_,_ = run(f"tar -tzf {latest} | grep -E '^(usr/bin/|lib/|usr/lib/|boot/|var/lib/dpkg)' | head -3")
print("系统文件泄露检查(应为空):", repr(o.strip()))

print("\n===== [3] 恢复智能逻辑 (安全解包到 /tmp, 不触碰生产) =====")
run("rm -rf /tmp/xcfui_verify && mkdir -p /tmp/xcfui_verify")
run(f"tar -xzf {latest} -C /tmp/xcfui_verify")
out,_,_ = run(r"grep -oE 'CN_ADDR = \"[0-9.]+\"' /tmp/xcfui_verify/opt/x-cfui/app.py 2>/dev/null | grep -oE '[0-9.]+' | head -1")
print("探测到旧 CN_ADDR:", out.strip() or "(空, 可能 app.py 已改结构)")
out,_,_ = run(r"python3 -c \"import json;d=json.load(open('/tmp/xcfui_verify/opt/x-cfui/state.json'));print('entry_token=',d.get('entry_token'),'| admin_user=',d.get('admin_user'))\"")
print("从备份读 entry_token/admin_user:", out.strip())
out,_,_ = run(r"grep -rl 'CN_ADDR' /tmp/xcfui_verify/opt/x-cfui/app.py | head -1 && grep -c 'CN_ADDR' /tmp/xcfui_verify/opt/x-cfui/app.py")
print("re-home sed 目标命中行数:", out.strip())
out,_,_ = run(r"test -f /tmp/xcfui_verify/opt/x-cfui/restore_xcfui.sh && echo '包内自带 restore 脚本: YES' || echo 'NO'")
print(out.strip())
run("rm -rf /tmp/xcfui_verify")

print("\n===== [4] 部署脚本随机凭据生成命令实测 (证明'全部随机') =====")
out,_,_ = run(r"""
echo -n 'rand_token: '; tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12; echo
echo -n 'rand_user : '; echo "cfui-$(tr -dc 'a-z0-9' < /dev/urandom | head -c 6)"
echo -n 'rand_pass : '; tr -dc 'a-zA-Z0-9!@#%^&*' < /dev/urandom | head -c 18; echo
echo -n 'uuid      : '; cat /proc/sys/kernel/random/uuid
""")
print(out.strip())

print("\n===== [5] 部署端到端可行性探测 =====")
out,_,_ = run("command -v docker && docker ps >/dev/null 2>&1 && echo 'DOCKER_OK' || echo 'NO_DOCKER'")
print("docker:", out.strip())
out,_,_ = run("command -v systemctl && echo 'systemctl_OK' || echo 'NO_systemctl'")
print("systemctl:", out.strip())

ssh.close()
print("\n===== 验证结束 =====")
