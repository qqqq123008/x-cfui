import paramiko, os, tarfile, json, base64

KEY = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/ssh_keys_backup/cn_id_ed25519.pem"
LOCAL_DEPLOY = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/xcfui-deploy.sh"
LOCAL_RESTORE = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/xcfui-restore.sh"
LOCAL_OUTDIR = r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/backups"
os.makedirs(LOCAL_OUTDIR, exist_ok=True)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("47.108.200.193", port=22022, username="root", key_filename=KEY, timeout=20)
sftp = ssh.open_sftp()
sftp.put(LOCAL_DEPLOY, "/tmp/v_xcfui_deploy.sh")
sftp.put(LOCAL_RESTORE, "/tmp/v_xcfui_restore.sh")

def run(c, timeout=150):
    i, o, e = ssh.exec_command(c, timeout=timeout)
    return o.read().decode('utf-8', 'replace'), e.read().decode('utf-8', 'replace'), o.channel.recv_exit_status()

print("===== 1) xcfui-restore.sh list 动作(新加, 应列出 CN /root 下的包) =====")
out, err, rc = run("bash /tmp/v_xcfui_restore.sh list 2>&1")
print(out.strip())
if err.strip(): print("ERR:", err[:300])

print("\n===== 2) 部署文件: 随机凭据函数实跑(extract 内嵌 deploy, 仅测 rand 函数) =====")
TEST_DEPLOY = r'''
set -e
X=/tmp/v_xcfui_deploy.sh
WORK=$(mktemp -d)
extract(){ awk -v s="$1" -v e="$2" 'BEGIN{p=0} $0==s{p=1;next} $0==e{p=0} p{print}' "$0" | base64 -d > "$3"; }
extract __APP_START__ __APP_END__ "$WORK/app.py"
extract __DEPLOY_START__ __DEPLOY_END__ "$WORK/deploy.sh"
# 仅 source 随机函数定义(不执行部署主体)
source <(awk '/^rand_token\(\)/{f=1} f{print} /^CLIENT_UUID=/{f=0}' "$WORK/deploy.sh")
echo "rand_token样例: $(rand_token)"
echo "rand_user样例: $(rand_user)"
echo "rand_pass样例: $(rand_pass)"
echo "uuid样例: $(cat /proc/sys/kernel/random/uuid)"
rm -rf "$WORK"
'''
with open(r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/_t.sh", "w", newline="\n") as f:
    f.write(TEST_DEPLOY)
sftp.put(r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/_t.sh", "/tmp/_t.sh")
out, err, rc = run("bash /tmp/_t.sh 2>&1")
print(out.strip())
if err.strip(): print("ERR:", err[:300])

print("\n===== 3) xcfui-restore.sh backup 动作(实跑生成一份新包) =====")
out, err, rc = run("bash /tmp/v_xcfui_restore.sh backup 2>&1 | tail -3")
print(out.strip())
pkg, _, _ = run("ls -t /root/xcfui_backup_*.tar.gz 2>/dev/null | head -1")
pkg = pkg.strip()
print("生成的包:", pkg)
members, _, _ = run(f"echo 成员数=$(tar -tzf {pkg} | wc -l)")

print("\n===== 4) 恢复逻辑安全验证(解包到 /tmp, 不执行真实 restore) =====")
SAFE = f'''
set -e
T=/tmp/xcfui_safe; rm -rf $T; mkdir -p $T
tar -xzf {pkg} -C $T
APP=$T/opt/x-cfui/app.py
ST=$T/opt/x-cfui/state.json
OLD_CN=$(grep -oE 'CN_ADDR = "[0-9.]+"' $APP 2>/dev/null | grep -oE '[0-9.]+' | head -1)
ET=$(python3 -c "import json;print(json.load(open('$ST')).get('entry_token',''))" 2>/dev/null)
AU=$(python3 -c "import json;print(json.load(open('$ST')).get('admin_user',''))" 2>/dev/null)
echo "OLD_CN_IP=$OLD_CN"
echo "ENTRY_TOKEN=$ET"
echo "ADMIN_USER=$AU"
echo "re-home命中行数=$(grep -c 'CN_ADDR' $APP)"
echo "内嵌restore存在=$(test -f $T/opt/x-cfui/_restore_xcfui.sh && echo YES || echo NO)"
rm -rf $T
'''
with open(r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/_t.sh", "w", newline="\n") as f:
    f.write(SAFE)
sftp.put(r"C:/Users/qq123008/WorkBuddy/Claw/xray_admin/_t.sh", "/tmp/_t.sh")
out, err, rc = run("bash /tmp/_t.sh 2>&1")
print(out.strip())
if err.strip(): print("ERR:", err[:300])

print("\n===== 5) 下载该真实备份包到本地(供你以后搬家用) =====")
base = os.path.basename(pkg)
local_path = os.path.join(LOCAL_OUTDIR, base)
sftp.get(pkg, local_path)
print("已下载:", local_path, "大小:", os.path.getsize(local_path), "字节")
# 校验下载的包内嵌 restore 与 state
with tarfile.open(local_path) as t:
    names = t.getnames()
    sj = [n for n in names if n.endswith("state.json")]
    rj = [n for n in names if n.endswith("_restore_xcfui.sh")]
    data = json.loads(t.extractfile(sj[0]).read().decode())
    print("  本地包 state.json entry_token =", repr(data.get("entry_token")),
          "| admin_user =", repr(data.get("admin_user")),
          "| 出口节点数 =", len(data.get("exits", [])),
          "| 入站数 =", len(data.get("inbounds", [])))
    print("  本地包含 _restore_xcfui.sh ?", bool(rj), "| 成员总数 =", len(names))

# 清理 CN 上的测试包与临时文件, 保持服务器整洁
run(f"rm -f {pkg}")
run("rm -f /tmp/v_xcfui_deploy.sh /tmp/v_xcfui_restore.sh /tmp/_t.sh")
sftp.close(); ssh.close()
print("\nALL DONE — CN 测试包已清理, 本地已留真实备份包。")
