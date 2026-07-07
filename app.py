#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x-cfui 管理面板 (入口控制器)
零依赖: 仅用 Python 标准库 (http.server / ssl / base64 / subprocess)
适配架构: 多端口入口 -> 不同出口节点

功能:
  - 入口加密: 每个入口端口支持 none / reality(伪装) / tls(SSL)
  - 中继加密: 入口 -> 出口节点 支持 tls(默认) / none, 自动向出口推送 TLS 配置
  - 一键 BBR: 对任意出口节点 SSH 开启 BBR 拥塞控制
  - 防火墙管理: 开关防火墙 / 端口放行 / 禁止 (入口本地 + 各出口 SSH)
  - 开机自启核验: 逐项验证 Xray / BBR / 防火墙 是否开机自动启动
  - 客户端伪装指纹 (uTLS fp) 注册到面板
  - 主题(白天/夜间) 与 语言(中文/英文) 切换
  - 账号 / 密令入口 / 客户端链接 均可在面板查看与修改
"""
import json
import os
import base64
import secrets
import subprocess
import shutil
import urllib.parse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

BASE = "/opt/x-cfui"
MACHINE_BACKUP_DIR = "/opt/x-cfui/machine_backups"   # 每台服务器本地存放整机备份
MACHINE_JOB_FILE = os.path.join(BASE, "machine_backup_jobs.json")  # 面板侧任务状态(持久化)
MACHINE_BACKUP_LOCK = threading.Lock()
MACHINE_JOB_FILE_LOCK = threading.Lock()
machine_jobs = {}   # target -> {state, started, finished, filename, size, rc, error}
STATE_FILE = os.path.join(BASE, "state.json")
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
XRAY_BIN = "/usr/local/bin/xray"
BACKUP_DIR = os.path.join(BASE, "backups")
DEFAULT_BACKUP = os.path.join(BACKUP_DIR, "default_backup.json")
UPLOAD_BACKUP = os.path.join(BACKUP_DIR, "uploaded_backup.json")
SERVICE = "xray"
ADMIN_USER = "admin"
PORT = 5000

BBR_CONF = """net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_retries1=3
net.ipv4.tcp_retries2=5
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_keepalive_time=30
net.ipv4.tcp_keepalive_intvl=5
net.ipv4.tcp_keepalive_probes=3
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
"""

SERVICE_UNIT = """[Unit]
Description=x-cfui Xray Admin Panel
After=network.target

[Service]
User=root
WorkingDirectory=/opt/x-cfui
ExecStart=/usr/bin/python3 /opt/x-cfui/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""

# 出口服务器上的 Xray 服务单元 (注意: 不能复用 SERVICE_UNIT, 否则出口会去跑面板代码)
XRAY_SERVICE_UNIT = """[Unit]
Description=Xray Proxy Service (exit node)
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""

# 默认伪装域名池 (Reality 入口用, 选择高信誉站点)
REALITY_TARGETS = ["www.microsoft.com", "www.apple.com", "github.com", "www.cloudflare.com"]

# ufw 启用前自动放行的关键端口 (避免锁死 SSH/面板/代理)
FW_ALLOW_BASE = ["22/tcp", "5000/tcp", "443/tcp", "8443/tcp", "10443/tcp"]

# ---- SSH 安全加固相关 (面板管理密钥 / 服务器地址映射) ----
PANEL_KEY = "/root/.ssh/xcfui_ed25519"          # 面板自身的管理私钥(入口机上生成)
PANEL_PUB = PANEL_KEY + ".pub"
SSH_KEY_DIR = "/opt/x-cfui/ssh_keys"            # 用户上传的连接用密钥库(用于新出口等)
HOST_KEY_DIR = "/opt/x-cfui/host_keys"          # 三台服务器当前登录私钥(供面板下载备份)
# 节点地址不再写死任何生产 IP: 运行时完全由 state.json 的 cn_addr 驱动。
# 这里仅保留占位默认值(空串); deploy/restore 脚本都会把真实公网 IP 写入 state.json。
CN_ADDR = ""


def _ssh_args(user, port, host, key=None):
    """构造 sshpass ssh 命令; 密钥优先级: 指定 key > 面板管理密钥 PANEL_KEY > 密码(sshpass)。调用方需设置 env['SSHPASS']"""
    args = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key and os.path.exists(key):
        args += ["-i", key]
    elif os.path.exists(PANEL_KEY):
        args += ["-i", PANEL_KEY]
    args += ["-p", str(port), f"{user}@{host}", "bash -s"]
    return args


def _resolve_key(name):
    """把密钥库中的文件名解析为安全绝对路径(仅允许库目录内的纯文件名, 防路径穿越)"""
    if not name:
        return None
    base = os.path.basename(name)
    if not base or base in (".", ".."):
        return None
    p = os.path.join(SSH_KEY_DIR, base)
    return p if os.path.abspath(p).startswith(os.path.abspath(SSH_KEY_DIR) + os.sep) else None


# ---- SSH 密钥库 (用户上传的连接用私钥: 用于新出口/自定义连接) ----
def list_ssh_keys():
    """列出密钥库中的私钥文件(名称/大小/修改时间), 不含内容"""
    try:
        os.makedirs(SSH_KEY_DIR, exist_ok=True)
        items = []
        for fn in sorted(os.listdir(SSH_KEY_DIR)):
            p = os.path.join(SSH_KEY_DIR, fn)
            if os.path.isfile(p) and not fn.endswith(".pub"):
                stt = os.stat(p)
                items.append({"name": fn, "size": stt.st_size,
                              "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stt.st_mtime))})
        return {"ok": True, "keys": items}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def _key_in_use(name):
    """返回正在引用该密钥的出口名称列表"""
    st = load_state(); used = []
    for ex in st.get("exits", []):
        if ex.get("ssh_key") == name:
            used.append(ex.get("name", ex.get("address", "")))
    return used


def upload_ssh_key(name, content_b64):
    """保存上传的私钥到密钥库, 权限 600。name 仅允许纯文件名(字母/数字/./-/_)。"""
    base = (name or "").strip()
    if not base:
        return {"ok": False, "msg": "密钥文件名不能为空"}
    if "/" in base or "\\" in base or not all(c.isalnum() or c in "._-" for c in base):
        return {"ok": False, "msg": "密钥文件名不合法(仅允许字母/数字/./-/_，且不能含路径)"}
    try:
        raw = base64.b64decode(content_b64)
    except Exception:
        return {"ok": False, "msg": "密钥内容 base64 解码失败"}
    text = raw.decode("utf-8", errors="replace")
    head = text.lstrip().lower()
    if not ("-----begin" in head or head.startswith("ssh-") or "begin openssh" in head):
        return {"ok": False, "msg": "不是有效的 SSH 私钥(需以 -----BEGIN 或 ssh- 开头)"}
    os.makedirs(SSH_KEY_DIR, exist_ok=True)
    p = os.path.join(SSH_KEY_DIR, base)
    tmp = p + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    return {"ok": True, "name": base, "size": os.path.getsize(p)}


def delete_ssh_key(name):
    """删除密钥库中的密钥(防路径穿越)。若正被出口引用则拒绝。"""
    p = _resolve_key(name)
    if not p or not os.path.exists(p):
        return {"ok": False, "msg": "密钥不存在"}
    used = _key_in_use(os.path.basename(p))
    if used:
        return {"ok": False, "msg": "该密钥正被出口使用: " + ", ".join(used) + "，请先改为其它密钥或删除该出口", "in_use": used}
    try:
        os.remove(p)
        return {"ok": True, "name": os.path.basename(p)}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def ensure_panel_key():
    """在入口(面板所在)生成 ed25519 管理密钥对, 供面板免密码管理各服务器"""
    if os.path.exists(PANEL_KEY) and os.path.exists(PANEL_PUB):
        return True
    try:
        os.makedirs("/root/.ssh", exist_ok=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "xcfui-panel",
                        "-f", PANEL_KEY], capture_output=True, text=True, timeout=30)
    except Exception:
        return False
    return os.path.exists(PANEL_KEY)


def panel_pubkey():
    if not os.path.exists(PANEL_PUB):
        if not ensure_panel_key():
            return ""
    try:
        return open(PANEL_PUB).read().strip()
    except Exception:
        return ""


def resolve_target(target):
    """返回 ('entry', None) 或 ('exit', exit_dict) 或 ('unknown', None)"""
    if target == "entry" or target == "cn":
        return "entry", None
    st = load_state()
    for ex in st.get("exits", []):
        if ex.get("tag") == target:
            return "exit", ex
    return "unknown", None


def load_state():
    if not os.path.exists(STATE_FILE):
        init = {
            "admin_user": ADMIN_USER,
            "admin_pass": secrets.token_urlsafe(12),
            "entry_token": "aa888888",
            "client_uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "client_fp": "chrome",
            "cn_ssh_port": 22,
            "cn_addr": CN_ADDR,
            "exits": [],
            "inbounds": [],
        }
        save_state(init)
        return init
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        st = json.load(f)
    st.setdefault("admin_user", ADMIN_USER)
    st.setdefault("entry_token", "aa888888")
    st.setdefault("client_fp", "chrome")
    for ex in st.get("exits", []):
        ex.setdefault("relay_security", "tls")
        ex.setdefault("pushed_relay", None)
        ex.setdefault("bbr", False)
    for ib in st.get("inbounds", []):
        ib.setdefault("security", "none")
    st.setdefault("cn_ssh_port", 22)
    st.setdefault("cn_addr", CN_ADDR)
    st.setdefault("routing_rules", [])
    st.setdefault("smart_routing", False)
    # migrate single public_host string -> public_hosts list
    if "public_host" in st and "public_hosts" not in st:
        h = st.pop("public_host", "")
        if h:
            st["public_hosts"] = [h]
    st.setdefault("public_hosts", [])
    st.setdefault("site_title", "x-cfui")
    st.setdefault("site_footer", "QQ: 123008")
    return st


def save_state(state):
    os.makedirs(BASE, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# ===================== 节点地址: 运行时优先从 state.json 读取 =====================
# CN_ADDR 从 state.json.cn_addr 读取(由 deploy/restore 脚本自动写入)
# 且 bug 会随备份包一起被打包。现在改为优先读 state.json 的 cn_addr/sg_addr/ru_addr 字段,
# 恢复时只需更新数据文件(写 state.json)即可改 IP, 无需改动源码本身。源码中的字面量仅作首次部署兜底。
try:
    _node_state = load_state()
    if _node_state.get("cn_addr"):
        CN_ADDR = _node_state["cn_addr"]
except Exception:
    pass


def gen_reality_keypair():
    """生成 Reality 的 x25519 密钥对, 返回 (privateKey, publicKey)"""
    r = subprocess.run([XRAY_BIN, "x25519"], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError("xray x25519 执行失败: " + r.stderr)
    priv = pub = None
    for line in r.stdout.splitlines():
        # 注意: xray 输出格式为 "PrivateKey:" / "Password (PublicKey):" (无空格)
        if line.startswith("PrivateKey:"):
            priv = line.split(":", 1)[1].strip()
        elif line.startswith("Password (PublicKey):"):
            pub = line.split(":", 1)[1].strip()
    if not (priv and pub):
        raise RuntimeError("无法解析 xray x25519 输出: " + r.stdout)
    return priv, pub


def gen_short_id():
    return secrets.token_hex(8)  # 16 hex 字符 (8 字节)


def ensure_cn_cert():
    """自签证书 (入口用 tls 时)"""
    cert = "/usr/local/etc/xray/cn_cert.pem"
    key = "/usr/local/etc/xray/cn_key.pem"
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", key],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-days", "3650", "-key", key,
                    "-out", cert, "-subj", "/CN=www.apple.com"], check=True, capture_output=True)
    return cert, key


# ------------------------------------------------------------------- 出口配置
def render_exit_config(exit_info):
    """生成出口服务器的 xray config (接收入口中继)"""
    sec = exit_info.get("relay_security", "tls")
    inbound = {
        "port": int(exit_info["port"]),
        "listen": "0.0.0.0",
        "protocol": "vless",
        "settings": {"clients": [{"id": exit_info["uuid"]}], "decryption": "none"},
        "sniffing": {"enabled": False},
    }
    if sec == "tls":
        inbound["streamSettings"] = {
            "network": "tcp", "security": "tls",
            "tlsSettings": {"certificates": [
                {"certificateFile": "/usr/local/etc/xray/cert.pem",
                 "keyFile": "/usr/local/etc/xray/key.pem"}]}
        }
    else:
        inbound["streamSettings"] = {"network": "tcp", "security": "none"}
    return {
        "log": {"loglevel": "info"},
        "inbounds": [inbound],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}, "tag": "direct"}],
    }


def push_exit_config(exit_info, ssh_pass, ssh_user="root", ssh_port=22, key=None):
    """SSH 到出口, 写入 TLS/明文 入站配置 + 证书 + BBR, 重启 xray。返回 (ok, log)"""
    cfg_str = json.dumps(render_exit_config(exit_info), indent=2, ensure_ascii=False)
    script = f"""set -e
export DEBIAN_FRONTEND=noninteractive
mkdir -p /usr/local/etc/xray
# 自签证书 (中继 TLS 用)
if [ ! -f /usr/local/etc/xray/cert.pem ]; then
  apt-get install -y -qq openssl >/dev/null 2>&1 || true
  openssl ecparam -genkey -name prime256v1 -out /usr/local/etc/xray/key.pem 2>/dev/null
  openssl req -new -x509 -days 3650 -key /usr/local/etc/xray/key.pem -out /usr/local/etc/xray/cert.pem -subj "/CN=www.apple.com" 2>/dev/null
fi
cat > /usr/local/etc/xray/config.json <<'XEOF'
{cfg_str}
XEOF
cat > /etc/sysctl.d/99-bbr.conf <<'BEOF'
{BBR_CONF}BEOF
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
modprobe tcp_bbr 2>/dev/null || true
# 确保出口 xray 服务单元正确 (不能用面板的 SERVICE_UNIT)
cat > /etc/systemd/system/xray.service <<'XSEOF'
{XRAY_SERVICE_UNIT}XSEOF
systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 2
echo "EXIT_DONE cca=$(sysctl -n net.ipv4.tcp_congestion_control)"
"""
    try:
        env = dict(os.environ)
        env["SSHPASS"] = ssh_pass
        proc = subprocess.run(
            _ssh_args(ssh_user, ssh_port, exit_info['address'], _resolve_key(key)),
            input=script, capture_output=True, text=True, env=env, timeout=300)
        if proc.returncode != 0:
            return False, f"推送失败 (rc={proc.returncode}):\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
        return True, proc.stdout
    except subprocess.TimeoutExpired:
        return False, "推送超时 (300s)"
    except FileNotFoundError:
        return False, "入口缺少 sshpass, 请先: apt-get install -y sshpass"
    except Exception as e:
        return False, f"异常: {e}"


def enable_bbr(address, ssh_pass, ssh_user="root", ssh_port=22, key=None):
    """SSH 到出口开启 BBR, 返回 (ok, log)"""
    script = f"""set -e
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-bbr.conf <<'BEOF'
{BBR_CONF}BEOF
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
modprobe tcp_bbr 2>/dev/null || true
sleep 1
echo "BBR_CCA=$(sysctl -n net.ipv4.tcp_congestion_control)"
lsmod | grep -q tcp_bbr && echo "BBR_MOD=loaded" || echo "BBR_MOD=missing"
"""
    try:
        env = dict(os.environ)
        env["SSHPASS"] = ssh_pass
        proc = subprocess.run(
            _ssh_args(ssh_user, ssh_port, address, _resolve_key(key)),
            input=script, capture_output=True, text=True, env=env, timeout=120)
        if proc.returncode != 0:
            return False, f"开启失败:\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
        return True, proc.stdout
    except Exception as e:
        return False, f"异常: {e}"


def provision_exit(exit_info, ssh_pass, ssh_port=22, ssh_user="root", key=None):
    """SSH 到新出口服务器, 完整部署: 装 Xray + TLS 入站 + BBR。返回 (ok, log)"""
    ip = exit_info["address"]
    cfg_str = json.dumps(render_exit_config(exit_info), indent=2, ensure_ascii=False)
    setup_script = f"""set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq unzip curl openssl >/dev/null 2>&1 || true
cd /tmp
curl -fsSL -o Xray-linux-64.zip https://ghfast.top/https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip || curl -fsSL -o Xray-linux-64.zip https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip
mkdir -p /usr/local/etc/xray /usr/local/bin
unzip -o Xray-linux-64.zip -d /tmp/xe >/dev/null
cp /tmp/xe/xray /usr/local/bin/xray
chmod +x /usr/local/bin/xray
rm -rf /tmp/xe Xray-linux-64.zip
openssl ecparam -genkey -name prime256v1 -out /usr/local/etc/xray/key.pem 2>/dev/null
openssl req -new -x509 -days 3650 -key /usr/local/etc/xray/key.pem -out /usr/local/etc/xray/cert.pem -subj "/CN=www.apple.com" 2>/dev/null
cat > /usr/local/etc/xray/config.json <<'XEOF'
{cfg_str}
XEOF
cat > /etc/systemd/system/xray.service <<'SEOF'
{XRAY_SERVICE_UNIT}SEOF
cat > /etc/sysctl.d/99-bbr.conf <<'BEOF'
{BBR_CONF}BEOF
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
modprobe tcp_bbr 2>/dev/null || true
ufw disable >/dev/null 2>&1 || true
iptables -F >/dev/null 2>&1 || true
iptables -P INPUT ACCEPT >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2
echo "DONE: $(/usr/local/bin/xray version | head -1) cca=$(sysctl -n net.ipv4.tcp_congestion_control)"
"""
    try:
        env = dict(os.environ)
        env["SSHPASS"] = ssh_pass
        proc = subprocess.run(
            _ssh_args(ssh_user, ssh_port, ip, _resolve_key(key)),
            input=setup_script, capture_output=True, text=True, env=env, timeout=300)
        if proc.returncode != 0:
            return False, f"部署失败 (rc={proc.returncode}):\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
        return True, proc.stdout
    except subprocess.TimeoutExpired:
        return False, "部署超时 (300s)"
    except FileNotFoundError:
        return False, "入口服务器缺少 sshpass, 请先: apt-get install -y sshpass"
    except Exception as e:
        return False, f"异常: {e}"


# ------------------------------------------------------------------- 防火墙管理
def build_fw_script(action=None, port=None, proto="tcp", extra_ports=None):
    """生成防火墙操作脚本 (统一用于本地/远程)。action: enable/disable/allow/deny/None(仅查状态)"""
    head = ["export DEBIAN_FRONTEND=noninteractive"]
    if action is not None:
        # 仅在执行实际操作时才安装 ufw, 单纯查状态不应触发安装
        head.append("command -v ufw >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq ufw) >/dev/null 2>&1")
    body = []
    if action == "enable":
        for p in FW_ALLOW_BASE:
            body.append(f"ufw allow {p} >/dev/null 2>&1")
        for ep in (extra_ports or []):
            body.append(f"ufw allow {ep}/tcp >/dev/null 2>&1")
        body.append("ufw --force enable >/dev/null 2>&1")
    elif action == "disable":
        body.append("ufw --force disable >/dev/null 2>&1")
    elif action == "allow" and port:
        body.append(f"ufw allow {port}/{proto} >/dev/null 2>&1")
    elif action == "deny" and port:
        body.append(f"ufw deny {port}/{proto} >/dev/null 2>&1")
    tail = [
        'echo "INSTALLED=$(command -v ufw >/dev/null 2>&1 && echo yes || echo no) ACTIVE=$(ufw status 2>/dev/null | head -1 | grep -qi active && echo yes || echo no)"',
        'echo "---RULES---"',
        'ufw status numbered 2>/dev/null | sed -n "4,100p"',
    ]
    return "\n".join(head + body + tail)


def _parse_fw_status(out):
    d = {"installed": False, "active": False, "rules": []}
    lines = out.split("\n")
    for ln in lines:
        if ln.startswith("INSTALLED="):
            d["installed"] = ("yes" in ln)
        # build_fw_script 将 INSTALLED=与 ACTIVE= 输出在同一行, 故用子串匹配
        if "ACTIVE=yes" in ln:
            d["active"] = True
        elif "ACTIVE=no" in ln:
            d["active"] = False
        if ln.startswith("STATUS="):
            d["active"] = ("active" in ln)
    if "---RULES---" in lines:
        idx = lines.index("---RULES---")
        for ln in lines[idx + 1:]:
            if ln.strip():
                d["rules"].append(ln.strip())
    return d


def fw_status_local():
    try:
        script = build_fw_script(None)
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
        res = _parse_fw_status(proc.stdout)
        res["ok"] = True
        return res
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def fw_operate_local(action, port=None, proto="tcp", extra_ports=None):
    try:
        script = build_fw_script(action, port, proto, extra_ports)
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120)
        res = _parse_fw_status(proc.stdout)
        res["ok"] = True
        return res
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def fw_status_remote(address, ssh_pass="", ssh_user="root", ssh_port=22, key=None):
    """远程查询防火墙状态。优先指定 key > 面板管理密钥, 密码回退。"""
    if not shutil.which("sshpass"):
        return {"ok": False, "msg": "入口缺少 sshpass"}
    script = build_fw_script(None)
    try:
        env = dict(os.environ); env["SSHPASS"] = ssh_pass or ""
        proc = subprocess.run(_ssh_args(ssh_user, ssh_port, address, _resolve_key(key)),
                              input=script, capture_output=True, text=True, env=env, timeout=60)
        if proc.returncode != 0:
            return {"ok": False, "msg": proc.stderr.strip() or "SSH 失败"}
        res = _parse_fw_status(proc.stdout)
        res["ok"] = True
        return res
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def fw_operate_remote(address, ssh_pass="", action=None, port=None, proto="tcp",
                      ssh_user="root", ssh_port=22, extra_ports=None, key=None):
    """远程操作防火墙。优先指定 key > 面板管理密钥, 密码回退。"""
    if not shutil.which("sshpass"):
        return {"ok": False, "msg": "入口缺少 sshpass"}
    script = build_fw_script(action, port, proto, extra_ports)
    try:
        env = dict(os.environ); env["SSHPASS"] = ssh_pass or ""
        proc = subprocess.run(_ssh_args(ssh_user, ssh_port, address, _resolve_key(key)),
                              input=script, capture_output=True, text=True, env=env, timeout=120)
        if proc.returncode != 0:
            return {"ok": False, "msg": proc.stderr.strip() or "SSH 失败"}
        res = _parse_fw_status(proc.stdout)
        res["ok"] = True
        return res
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def build_fw_harden_script(allow_ports):
    """一键加固脚本: 放行给定端口(端口/协议), 其余全部拒绝(default deny incoming)。"""
    head = ["export DEBIAN_FRONTEND=noninteractive",
            "command -v ufw >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq ufw) >/dev/null 2>&1"]
    body = [f"ufw allow {p} >/dev/null 2>&1" for p in allow_ports]
    body.append("ufw default deny incoming >/dev/null 2>&1")   # 拒绝其余未使用端口
    body.append("ufw --force enable >/dev/null 2>&1")
    tail = [
        'echo "INSTALLED=$(command -v ufw >/dev/null 2>&1 && echo yes || echo no) ACTIVE=$(ufw status 2>/dev/null | head -1 | grep -qi active && echo yes || echo no)"',
        'echo "---RULES---"',
        'ufw status numbered 2>/dev/null | sed -n "4,100p"',
    ]
    return "\n".join(head + body + tail)


def _harden_allow_list(ports):
    """从监听端口中筛出需放行的(端口/协议): 跳过仅回环地址监听的端口(127.* / [::1] / %lo)。"""
    seen, out = set(), []
    for p in ports:
        addr = (p.get("addr") or "")
        base = addr.split("%")[0]
        if addr.startswith("127.") or "%lo" in addr or base in ("[::1]", "::1"):
            continue
        key = (p["port"], p["proto"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{p['port']}/{p['proto']}")
    return out


def fw_harden(target, allow_ports):
    """对单台服务器执行一键加固 (入口本地 / SSH 出口)。"""
    script = build_fw_harden_script(allow_ports)
    rc, out, err = ssh_exec(target, script, timeout=120)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "执行失败"), "allowed": allow_ports}
    # 二次状态查询(全新连接): ufw --force enable 可能杀死本脚本的 SSH 会话,
    # 导致首次回显的 active 误报为 False, 故用独立查询拿到真实状态
    rc2, out2, _ = ssh_exec(target, build_fw_script(None), timeout=60)
    status = _parse_fw_status(out2) if rc2 == 0 else _parse_fw_status(out)
    return {"ok": True, "allowed": allow_ports, **status}


def fw_harden_all():
    """对三台服务器依次一键加固: 放行各自正在监听的全部端口, 拒绝其余端口。"""
    res = {}
    st = load_state()
    for tgt in ["entry"] + [e["tag"] for e in st.get("exits", [])]:
        lp = get_listening_ports(tgt)
        if not lp.get("ok"):
            res[tgt] = {"ok": False, "msg": lp.get("msg", "获取端口失败")}
            continue
        allow = _harden_allow_list(lp["ports"])
        res[tgt] = fw_harden(tgt, allow)
    return res


# ------------------------------------------------------------------- GeoIP 有效性校验
_GEOIP_CACHE = {"mtime": 0.0, "ok": None, "ts": 0.0}
def geoip_is_valid():
    """校验 geoip.dat 是否真实可被 xray 加载(而非仅文件存在)。

    仅判断 os.path.exists() 会误报: 放错格式(如新版 rule-set)的 geoip.dat 虽存在,
    但 xray 加载时仍报 'code not found', 应用 GeoIP 规则会拖崩 xray。
    故用 `xray run -test` 真实加载一条 geoip:cn 规则作为唯一标准, 结果按文件 mtime 缓存(10min)。
    """
    import tempfile, copy
    paths = ("/usr/local/share/xray/geoip.dat", "/usr/local/etc/xray/geoip.dat")
    fp = next((p for p in paths if os.path.exists(p)), None)
    if not fp:
        return False
    try:
        mtime = os.path.getmtime(fp)
    except OSError:
        return False
    now = time.time()
    if _GEOIP_CACHE["mtime"] == mtime and _GEOIP_CACHE["ok"] is not None and (now - _GEOIP_CACHE["ts"]) < 600:
        return _GEOIP_CACHE["ok"]
    ok = False
    cfg = None
    try:
        with open(XRAY_CONFIG) as f:
            base = json.load(f)  # 用真实配置(已验证可用), 仅临时注入一条 geoip:cn 规则
        cfg_obj = copy.deepcopy(base)
        rule = {"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"}
        cfg_obj.setdefault("routing", {}).setdefault("rules", []).insert(0, rule)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg_obj, f); cfg = f.name
        proc = subprocess.run([XRAY_BIN, "run", "-test", "-config", cfg],
                              capture_output=True, text=True, timeout=30)
        # 唯一失败信号: xray 报 'code not found' -> 文件不含该国家代码(格式不对)
        ok = "code not found" not in (proc.stdout + proc.stderr)
    except Exception:
        ok = False
    finally:
        if cfg:
            try: os.remove(cfg)
            except OSError: pass
    _GEOIP_CACHE.update(mtime=mtime, ok=ok, ts=now)
    return ok


# ------------------------------------------------------------------- 开机自启核验
def autostart_local():
    def se(s):
        r = subprocess.run(["systemctl", "is-enabled", s], capture_output=True, text=True)
        return r.stdout.strip() == "enabled"
    def sa(s):
        r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
        return r.stdout.strip() == "active"
    g = subprocess.run(["grep", "-rEs", "tcp_congestion_control[[:space:]]*=[[:space:]]*bbr",
                        "/etc/sysctl.d/", "/etc/sysctl.conf"], capture_output=True, text=True)
    bbr_persist = bool(g.stdout.strip())
    cca = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
                         capture_output=True, text=True).stdout.strip()
    fw = subprocess.run(["bash", "-c", "command -v ufw >/dev/null 2>&1 && (ufw status 2>/dev/null | head -1) || echo none"],
                        capture_output=True, text=True).stdout.strip()
    fw_on = ("active" in fw) and ("none" not in fw)
    netf = subprocess.run(["systemctl", "is-enabled", "netfilter-persistent"],
                          capture_output=True, text=True).stdout.strip() == "enabled"
    return {"ok": True, "host": CN_ADDR, "name": "入口服务器",
            "xray_enabled": se("xray"), "xray_active": sa("xray"),
            "admin_enabled": se("x-cfui") or se("xray-admin"), "admin_active": sa("x-cfui") or sa("xray-admin"),
            "bbr_persist": bbr_persist, "bbr_active": (cca == "bbr"),
            "firewall_enabled": fw_on, "iptables_persist": netf,
            "port_forward": "xray 内部路由 (无 DNAT 端口转发)"}


def autostart_remote(address, ssh_pass="", ssh_user="root", ssh_port=22, key=None):
    """SSH 到出口服务器核验开机自启状态。优先指定 key > 面板管理密钥, 密码仅作回退。"""
    if not shutil.which("sshpass"):
        return {"ok": False, "msg": "入口缺少 sshpass"}
    script = '''XE=$(systemctl is-enabled xray 2>/dev/null)
XA=$(systemctl is-active xray 2>/dev/null)
BP=$(grep -rqs "tcp_congestion_control[[:space:]]*=[[:space:]]*bbr" /etc/sysctl.d/ /etc/sysctl.conf && echo yes || echo no)
BC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
FW=$(command -v ufw >/dev/null 2>&1 && (ufw status 2>/dev/null | head -1) || echo none)
NP=$(systemctl is-enabled netfilter-persistent 2>/dev/null)
printf "XE=%s\\nXA=%s\\nBP=%s\\nBC=%s\\nFW=%s\\nNP=%s" "$XE" "$XA" "$BP" "$BC" "$FW" "$NP"
'''
    env = dict(os.environ); env["SSHPASS"] = ssh_pass or ""
    last_err = ""
    try:
        for _ in range(2):  # 重试一次, 规避 ssh 会话抖动
            proc = subprocess.run(_ssh_args(ssh_user, ssh_port, address, _resolve_key(key)),
                                  input=script, capture_output=True, text=True, env=env, timeout=60)
            if proc.returncode != 0:
                last_err = proc.stderr.strip() or "SSH 失败"; continue
            d = {"ok": True, "host": address, "name": address}
            for kv in proc.stdout.strip().splitlines():  # 按行拆分(值内部空格不再破坏解析)
                if "=" in kv:
                    k, v = kv.split("=", 1); d[k] = v
            d["xray_enabled"] = (d.get("XE") == "enabled")
            d["xray_active"] = (d.get("XA") == "active")
            d["bbr_persist"] = (d.get("BP") == "yes")
            d["bbr_active"] = (d.get("BC") == "bbr")
            d["firewall_enabled"] = ("active" in d.get("FW", "")) and ("none" not in d.get("FW", ""))
            d["iptables_persist"] = (d.get("NP") == "enabled")
            d["port_forward"] = "xray 内部路由 (无 DNAT 端口转发)"
            d.pop("XE", None); d.pop("XA", None); d.pop("BP", None)
            d.pop("BC", None); d.pop("FW", None); d.pop("NP", None)
            return d
        return {"ok": False, "msg": last_err or "autostart 检测失败"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


# ------------------------------------------------------------------- 配置生成
def bbr_status():
    """返回本机 BBR 当前状态与是否开机持久化"""
    try:
        import subprocess
        cca = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        qdisc = subprocess.run(["sysctl", "-n", "net.core.default_qdisc"],
                              capture_output=True, text=True, timeout=10).stdout.strip()
        out = subprocess.run(["grep", "-rEs", "tcp_congestion_control[[:space:]]*=[[:space:]]*bbr",
                             "/etc/sysctl.d/", "/etc/sysctl.conf"],
                            capture_output=True, text=True, timeout=10).stdout.strip()
        persisted = bool(out)
        mod = subprocess.run(["sh", "-c", "lsmod | grep -q tcp_bbr && echo loaded || echo missing"],
                            capture_output=True, text=True, timeout=10).stdout.strip()
        return {"ok": True, "cca": cca, "qdisc": qdisc, "persisted": persisted,
                "boot_auto": persisted, "module": mod}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def bbr_status_remote(address, ssh_pass="", ssh_user="root", ssh_port=22, key=None):
    """SSH 到出口服务器检查 BBR 状态。优先指定 key > 面板管理密钥, 密码回退。"""
    if not shutil.which("sshpass"):
        return {"ok": False, "msg": "入口缺少 sshpass"}
    script = '''cca=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
if grep -rqs "tcp_congestion_control[[:space:]]*=[[:space:]]*bbr" /etc/sysctl.d/ /etc/sysctl.conf; then persisted=yes; else persisted=no; fi
if lsmod | grep -q tcp_bbr; then mod=loaded; else mod=missing; fi
echo "cca=$cca qdisc=$qdisc persisted=$persisted mod=$mod"
'''
    try:
        env = dict(os.environ); env["SSHPASS"] = ssh_pass or ""
        last_err = ""
        for _ in range(2):  # 重试一次, 规避 sshpass 偶发抖动导致空结果
            proc = subprocess.run(_ssh_args(ssh_user, ssh_port, address, _resolve_key(key)),
                                  input=script, capture_output=True, text=True, env=env, timeout=30)
            if proc.returncode != 0:
                last_err = proc.stderr.strip() or "SSH 失败"; continue
            d = {}
            for kv in proc.stdout.strip().split():
                if "=" in kv:
                    k,v = kv.split("=",1); d[k]=v
            if d.get("cca"):
                return {"ok": True, "cca": d.get("cca",""), "qdisc": d.get("qdisc",""),
                        "persisted": d.get("persisted")=="yes", "boot_auto": d.get("persisted")=="yes", "module": d.get("mod","")}
            last_err = "空输出(疑似 SSH 会话抖动)"
        return {"ok": False, "msg": last_err or "BBR 检测失败"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


# ------------------------------------------------------------------- SSH 安全加固
def ssh_exec(target, script, timeout=60):
    """在指定服务器上执行脚本: 入口本地执行, 出口通过面板管理密钥或密码 SSH"""
    kind, ex = resolve_target(target)
    if kind == "entry":
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    if kind == "exit" and ex:
        host = ex["address"]; user = ex.get("ssh_user", "root")
        pw = ex.get("ssh_pass", ""); port = ex.get("ssh_port", 22)
        env = dict(os.environ); env["SSHPASS"] = pw
        try:
            proc = subprocess.run(_ssh_args(user, port, host, _resolve_key(ex.get("ssh_key"))),
                                  input=script, capture_output=True, text=True, env=env, timeout=timeout)
            return proc.returncode, proc.stdout, proc.stderr
        except Exception as e:
            return -1, "", str(e)
    return -1, "", "target 解析失败"


# ---- 整机完整备份 (tar 全文件系统, 存于目标服务器本地) ----
def _load_machine_jobs():
    global machine_jobs
    try:
        if os.path.exists(MACHINE_JOB_FILE):
            with open(MACHINE_JOB_FILE, "r", encoding="utf-8") as f:
                machine_jobs = json.load(f) or {}
    except Exception:
        machine_jobs = {}
    return machine_jobs


def _save_machine_jobs():
    try:
        with MACHINE_JOB_FILE_LOCK:
            with open(MACHINE_JOB_FILE, "w", encoding="utf-8") as f:
                json.dump(machine_jobs, f, ensure_ascii=False)
    except Exception:
        pass


def _safe_machine_name(name):
    """仅允许 machine_full_*.tar.gz 形式的纯文件名, 防路径穿越"""
    base = os.path.basename(name or "")
    if not base or base != name:
        return None
    if not base.startswith("machine_full_") or not base.endswith(".tar.gz"):
        return None
    if "/" in base or "\\" in base or ".." in base:
        return None
    return base


def machine_backup_list(target):
    """列出目标服务器已生成的整机备份文件: [{name, size, mtime}]"""
    script = (
        'D=%s; mkdir -p "$D"; cd "$D" 2>/dev/null || exit 1\n'
        'for f in machine_full_*.tar.gz; do\n'
        '  [ -e "$f" ] || continue\n'
        '  sz=$(stat -c%%s "$f" 2>/dev/null || echo 0)\n'
        '  mt=$(stat -c%%Y "$f" 2>/dev/null || echo 0)\n'
        '  echo "FILE|$f|$sz|$mt"\n'
        'done\n' % MACHINE_BACKUP_DIR
    )
    rc, out, err = ssh_exec(target, script, timeout=40)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "查询失败")}
    files = []
    for line in out.strip().splitlines():
        if not line.startswith("FILE|"):
            continue
        _, name, sz, mt = line.split("|", 3)
        files.append({
            "name": name,
            "size": int(sz or 0),
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(mt or 0))),
        })
    files.sort(key=lambda x: x["name"], reverse=True)
    return {"ok": True, "files": files}


def _machine_backup_worker(target):
    """后台线程: 在目标服务器执行整机 tar 备份, 并更新任务状态"""
    global machine_jobs
    job = {"state": "running", "started": time.strftime("%Y-%m-%d %H:%M:%S"),
           "finished": "", "filename": "", "size": 0, "rc": None, "error": ""}
    with MACHINE_BACKUP_LOCK:
        machine_jobs[target] = job
        _save_machine_jobs()
    try:
        script = (
            'D=%s; mkdir -p "$D"\n'
            'TS=$(date +%%Y%%m%%d_%%H%%M%%S)\n'
            'TMP="$D/.inprogress_${TS}.tar.gz"\n'
            'FIN="$D/machine_full_${TS}.tar.gz"\n'
            'META="/opt/x-cfui/.machine_backup_meta"\n'
            'mkdir -p "$META"\n'
            # 导出活动防火墙规则 (iptables / nftables)
            'iptables-save > "$META/firewall_iptables.save" 2>/dev/null || true\n'
            'nft list ruleset > "$META/firewall_nft.save" 2>/dev/null || true\n'
            # 生成清单
            '{\n'
            '  echo "x-cfui 应用与配置备份 (不含 Debian 系统文件)";\n'
            '  echo "生成时间: $(date)"; echo "主机名: $(hostname)";\n'
            '  echo "包含: 面板设置(state.json)/防火墙/xray分流与证书/SSH密钥(身份+主机)/SSH加固/fail2ban/BBR/sysctl/nginx网站/系统服务";\n'
            '} > "$META/MANIFEST.txt"\n'
            # 构造要备份的路径清单 (完整应用与配置)
            'LIST=$(mktemp); EXCL=$(mktemp)\n'
            'echo "/opt/x-cfui/machine_backups" > "$EXCL"\n'
            'for p in \\\n'
            '  /opt/x-cfui \\\n'
            '  /usr/local/bin/xray \\\n'
            '  /usr/local/etc/xray \\\n'
            '  /etc/ssh \\\n'
            '  /root/.ssh \\\n'
            '  /etc/fail2ban \\\n'
            '  /etc/sysctl.d \\\n'
            '  /etc/systemd/system \\\n'
            '  /etc/nginx \\\n'
            '  /var/www/html \\\n'
            '  /var/spool/cron \\\n'
            '  /var/backups \\\n'
            '  /etc/nftables.conf \\\n'
            '  /etc/ufw \\\n'
            '  /etc/hostname \\\n'
            '  /etc/hosts \\\n'
            '  /etc/timezone \\\n'
            '  /etc/cron.d \\\n'
            '  /etc/cron.daily \\\n'
            '  /etc/cron.hourly \\\n'
            '  /etc/cron.weekly \\\n'
            '  /etc/cron.monthly \\\n'
            '  /etc/chrony \\\n'
            '  /etc/logrotate.d \\\n'
            '  /etc/security \\\n'
            '  /etc/avahi \\\n'
            '  /etc/rsyslog.d \\\n'
            '  /etc/inputrc \\\n'
            '  /etc/bash.bashrc \\\n'
            '  /etc/profile \\\n'
            '  /etc/skel \\\n'
            '  /etc/sudoers.d \\\n'
            '  /etc/modules-load.d \\\n'
            '  /opt/xray_admin \\\n'
            '  "$META" ; do\n'
            '  [ -e "$p" ] && echo "$p"\n'
            'done > "$LIST"\n'
            # 打包 (排除大文件/递归/临时; 含全部应用与配置)
            'tar --numeric-owner \\\n'
            '  --exclude="opt/x-cfui/machine_backups" \\\n'
            '  --exclude="opt/x-cfui/__pycache__" \\\n'
            '  --exclude="opt/x-cfui/app.py.bak.*" \\\n'
            '  --exclude="opt/x-cfui/machine_backup_jobs.json" \\\n'
            '  --exclude="usr/local/etc/xray/geoip.dat" \\\n'
            '  --exclude="usr/local/etc/xray/geosite.dat" \\\n'
            '  -czpf "$TMP" -X "$EXCL" -T "$LIST" >/dev/null 2>&1\n'
            'RC=$?\n'
            'rm -f "$LIST" "$EXCL"\n'
            'if [ "$RC" = "0" ] || [ "$RC" = "1" ]; then\n'
            '  mv -f "$TMP" "$FIN"\n'
            '  SZ=$(stat -c%%s "$FIN" 2>/dev/null || echo 0)\n'
            '  echo "RESULT DONE $(basename "$FIN") $SZ $RC"\n'
            'else\n'
            '  rm -f "$TMP"\n'
            '  echo "RESULT FAIL $RC"\n'
            'fi\n' % MACHINE_BACKUP_DIR
        )
        rc, out, err = ssh_exec(target, script, timeout=7200)
        line = ""
        for l in out.strip().splitlines():
            if l.startswith("RESULT "):
                line = l
        if line.startswith("RESULT DONE "):
            _, _, fname, sz, rc2 = line.split(" ", 4)
            with MACHINE_BACKUP_LOCK:
                machine_jobs[target] = {
                    "state": "done", "started": job["started"],
                    "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "filename": fname, "size": int(sz or 0),
                    "rc": int(rc2 or 0), "error": "",
                }
                _save_machine_jobs()
        else:
            msg = line or (err.strip() or "未知错误 (rc=%s)" % rc)
            with MACHINE_BACKUP_LOCK:
                machine_jobs[target] = {
                    "state": "error", "started": job["started"],
                    "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "filename": "", "size": 0, "rc": rc, "error": msg,
                }
                _save_machine_jobs()
    except Exception as e:
        with MACHINE_BACKUP_LOCK:
            machine_jobs[target] = {
                "state": "error", "started": job["started"],
                "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                "filename": "", "size": 0, "rc": None, "error": str(e),
            }
            _save_machine_jobs()


def machine_backup_start(target):
    """启动整机备份 (后台线程执行, 立即返回)。同一目标已有进行中任务则拒绝。"""
    kind, _ = resolve_target(target)
    if kind is None:
        return {"ok": False, "msg": "未知服务器目标"}
    with MACHINE_BACKUP_LOCK:
        cur = machine_jobs.get(target, {})
        if cur.get("state") == "running":
            return {"ok": False, "msg": "该服务器整机备份正在进行中, 请稍候"}
        # 清理旧的错误/完成态, 允许重新发起
        machine_jobs.pop(target, None)
    t = threading.Thread(target=_machine_backup_worker, args=(target,), daemon=True)
    t.start()
    return {"ok": True, "msg": "%s 备份已启动, 仅备份应用与配置 (不含 Debian 系统文件), 通常数十秒即可完成, 可在下方查看进度" % target.upper()}


def machine_backup_delete(target, filename):
    """删除目标服务器上的某个整机备份文件"""
    name = _safe_machine_name(filename)
    if not name:
        return {"ok": False, "msg": "非法文件名"}
    script = 'rm -f "%s/%s" && echo OK' % (MACHINE_BACKUP_DIR, name)
    rc, out, err = ssh_exec(target, script, timeout=40)
    if rc != 0 or "OK" not in out:
        return {"ok": False, "msg": (err.strip() or "删除失败")}
    return {"ok": True, "msg": "已删除备份: " + name}


def machine_backup_remote_size(target, filename):
    """查询远程备份文件大小(用于下载 Content-Length)"""
    name = _safe_machine_name(filename)
    if not name:
        return None
    script = 'stat -c%%s "%s/%s" 2>/dev/null || echo 0' % (MACHINE_BACKUP_DIR, name)
    rc, out, err = ssh_exec(target, script, timeout=30)
    if rc != 0:
        return None
    try:
        return int((out or "0").strip().splitlines()[-1])
    except Exception:
        return None


def machine_backup_stream(target, filename, handler):
    """把备份文件流式返回给浏览器。入口本地直读, 出口经 SSH cat 流式转发。"""
    name = _safe_machine_name(filename)
    if not name:
        handler._send(400, {"ok": False, "msg": "非法文件名"}); return
    path = os.path.join(MACHINE_BACKUP_DIR, name)
    content_type = "application/octet-stream"
    disp = 'attachment; filename="%s"' % name
    if target == "entry" or target == "cn":
        if not os.path.exists(path):            handler._send(404, {"ok": False, "msg": "备份文件不存在"}); return
        size = os.path.getsize(path)
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Disposition", disp)
        handler.send_header("Content-Length", str(size))
        handler.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                try:
                    handler.wfile.write(chunk)
                except Exception:
                    return
        return
    # 远程: 先校验存在, 再流式 cat
    size = machine_backup_remote_size(target, name)
    if size is None:
        handler._send(404, {"ok": False, "msg": "备份文件不存在或查询失败"}); return
    kind, ex = resolve_target(target)
    if kind == "exit" and ex:
        host = ex["address"]; user = ex.get("ssh_user", "root")
        pw = ex.get("ssh_pass", ""); port = ex.get("ssh_port", 22)
        env = dict(os.environ); env["SSHPASS"] = pw
        args = _ssh_args(user, port, host, _resolve_key(ex.get("ssh_key")))
        args = args[:-1] + ["cat %s/%s" % (MACHINE_BACKUP_DIR, name)]
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=env, bufsize=0)
        except Exception as e:
            handler._send(500, {"ok": False, "msg": "流式下载失败: " + str(e)}); return
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Disposition", disp)
        handler.send_header("Content-Length", str(size))
        handler.end_headers()
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                handler.wfile.write(chunk)
        except Exception:
            pass
        try:
            proc.stdout.close(); proc.stderr.close(); proc.wait(timeout=10)
        except Exception:
            pass
        return
    handler._send(400, {"ok": False, "msg": "目标解析失败"})


def ssh_status(target):
    kind, ex = resolve_target(target)
    if kind is None:
        return {"ok": False, "msg": "未知服务器目标"}
    script = '''PORT=$(grep -iE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config | head -1 | awk '{print $2}'); [ -z "$PORT" ] && PORT=22
PA=$(grep -iE '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config | head -1 | awk '{print $2}'); [ -z "$PA" ] && PA=yes
PK=$(grep -iE '^[[:space:]]*PubkeyAuthentication' /etc/ssh/sshd_config | head -1 | awk '{print $2}'); [ -z "$PK" ] && PK=yes
PR=$(grep -iE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config | head -1 | awk '{print $2}'); [ -z "$PR" ] && PR=yes
AK=$(test -f /root/.ssh/authorized_keys && wc -l < /root/.ssh/authorized_keys || echo 0)
FW=$(command -v ufw >/dev/null 2>&1 && (ufw status 2>/dev/null | head -1) || echo none)
FAIL=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
FAIL24=$(awk -v d="$(date -d '24 hours ago' '+%b %e %H:%M' 2>/dev/null)" '$0 >= d && /Failed password/' /var/log/auth.log 2>/dev/null | wc -l || echo 0)
echo "PORT=$PORT PA=$PA PK=$PK PR=$PR AK=$AK FW=$FW FAIL=$FAIL FAIL24=$FAIL24"
'''
    rc, out, err = ssh_exec(target, script, timeout=40)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "SSH 执行失败"), "raw": out}
    d = {"ok": True}
    for kv in out.strip().split():
        if "=" in kv:
            k, v = kv.split("=", 1); d[k] = v
    d["port"] = int(d.get("PORT") or 22)
    d["password_auth"] = d.get("PA", "yes")
    d["pubkey_auth"] = d.get("PK", "yes")
    d["permit_root"] = d.get("PR", "yes")
    d["authorized_keys"] = int(d.get("AK") or 0)
    d["firewall"] = d.get("FW", "none")
    d["fail_total"] = int(d.get("FAIL") or 0)
    d["fail_24h"] = int(d.get("FAIL24") or 0)
    return d


def get_listening_ports(target):
    """返回目标服务器所有监听端口: [{proto, addr, port, proc}]。通过 ssh_exec 在目标机执行 ss/netstat 实时查询。"""
    cmd = "ss -tulnpH 2>/dev/null || ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"
    rc, out, err = ssh_exec(target, cmd, timeout=40)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "执行失败"), "raw": out}
    ports = []
    for line in out.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State") or line.startswith("Proto"):
            continue
        parts = line.split()
        # ss 列: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        if ":" not in local:
            continue
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = ""
        if "users:(" in line:
            try:
                seg = line.split("users:(", 1)[1]
                proc = seg.split("(", 1)[1].split('"', 2)[1] if '"' in seg else seg.split("(", 1)[1].split(",")[0]
            except Exception:
                proc = ""
        ports.append({"proto": proto, "addr": addr, "port": int(port), "proc": proc})
    ports.sort(key=lambda x: (x["proto"], x["port"]))
    return {"ok": True, "ports": ports}


def _apply_ports(target, ports):
    """将 sshd 配置为仅监听给定端口列表(多端口用于过渡), 校验后重启"""
    ports_lines = "\n".join(f"echo 'Port {p}' >> $CFG" for p in ports)
    script = f'''CFG=/etc/ssh/sshd_config
cp -f $CFG ${{CFG}}.bak.$(date +%s)
sed -i -E '/^[[:space:]]*#?[Pp]ort[[:space:]]+/d' $CFG
{ports_lines}
sshd -t && echo CFG_OK || {{ echo CFG_FAIL; exit 1; }}
ufw status 2>/dev/null | head -1 | grep -qi active && ufw allow {ports[-1]}/tcp >/dev/null 2>&1
setsid bash -c 'sleep 2; systemctl restart ssh' >/dev/null 2>&1 < /dev/null &
echo RESTART_SCHEDULED
'''
    rc, out, err = ssh_exec(target, script, timeout=60)
    return rc == 0 and "CFG_OK" in out


def _probe_port(target, port):
    """探测目标服务器 SSH 端口是否可登录(用于端口修改后验证)"""
    kind, ex = resolve_target(target)
    if kind == "entry":
        proc = subprocess.run(
            ["bash", "-c", f"ss -tlnp 2>/dev/null | grep -q ':{port} ' && echo LISTEN_OK || echo LISTEN_NO"],
            capture_output=True, text=True, timeout=10)
        return "LISTEN_OK" in proc.stdout
    if kind == "exit" and ex:
        host = ex["address"]; user = ex.get("ssh_user", "root"); pw = ex.get("ssh_pass", "")
        env = dict(os.environ); env["SSHPASS"] = pw
        args = _ssh_args(user, port, host, _resolve_key(ex.get("ssh_key")))
        if args and args[-1] == "bash -s":
            args[-1] = "echo PROBE_OK"
        try:
            proc = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            return proc.returncode == 0 and "PROBE_OK" in proc.stdout
        except Exception:
            return False
    return False


def ssh_set_port(target, new_port):
    """安全修改 SSH 端口: 双端口过渡 -> 验证 -> 仅新端口; 失败自动回滚旧端口"""
    new_port = int(new_port)
    if not (1 <= new_port <= 65535):
        return {"ok": False, "msg": "端口范围必须为 1-65535"}
    kind, ex = resolve_target(target)
    if kind is None:
        return {"ok": False, "msg": "未知服务器目标"}
    cur = ssh_status(target)
    if not cur.get("ok"):
        return {"ok": False, "msg": "无法读取当前 SSH 端口: " + cur.get("msg", "")}
    old_port = cur["port"]
    if old_port == new_port:
        return {"ok": False, "msg": f"新端口与当前端口相同 ({old_port})"}
    if not _apply_ports(target, [old_port, new_port]):
        return {"ok": False, "msg": "sshd 配置校验失败, 未改动端口(避免锁死)"}
    time.sleep(4)
    if not _probe_port(target, new_port):
        _apply_ports(target, [old_port])
        time.sleep(3)
        return {"ok": False, "msg": f"新端口 {new_port} 验证失败(防火墙/监听异常), 已回滚至 {old_port}, 连接未中断"}
    _apply_ports(target, [new_port])
    time.sleep(3)
    st = load_state()
    if kind == "entry":
        st["cn_ssh_port"] = new_port
    else:
        for i, e in enumerate(st["exits"]):
            if e.get("address") == ex.get("address"):
                st["exits"][i]["ssh_port"] = new_port
    save_state(st)
    return {"ok": True, "msg": f"SSH 端口已从 {old_port} 改为 {new_port}, 已验证通过(旧端口已关闭)"}


def ssh_gen_key(target):
    """在目标服务器生成 ed25519 登录密钥, 公钥写入 authorized_keys, 私钥返回供下载"""
    kind, ex = resolve_target(target)
    if kind is None:
        return {"ok": False, "msg": "未知服务器目标"}
    script = '''TS=$(date +%s)
KF=/root/.ssh/xcfui_admin_$TS
mkdir -p /root/.ssh; chmod 700 /root/.ssh
ssh-keygen -t ed25519 -N "" -C "xcfui-admin-$TS" -f $KF >/dev/null 2>&1
chmod 600 $KF
touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
cat $KF.pub >> /root/.ssh/authorized_keys
echo "PUB=$(cat $KF.pub)"
echo "PRIV_BEGIN"
cat $KF
echo "PRIV_END"
rm -f $KF
'''
    rc, out, err = ssh_exec(target, script, timeout=40)
    if rc != 0:
        return {"ok": False, "msg": err.strip() or "密钥生成失败"}
    priv = pub = ""
    if "PRIV_BEGIN" in out and "PRIV_END" in out:
        priv = out.split("PRIV_BEGIN", 1)[1].split("PRIV_END", 1)[0].strip()
    for ln in out.splitlines():
        if ln.startswith("PUB="):
            pub = ln[4:].strip()
    if not priv:
        return {"ok": False, "msg": "未能读取私钥: " + out[:200]}
    # 持久化当前私钥到面板主机密钥库, 供"下载当前密钥"使用(与服务器临时文件删除解耦)
    persist_msg = ""
    try:
        os.makedirs(HOST_KEY_DIR, exist_ok=True)
        p = os.path.join(HOST_KEY_DIR, "host_%s.pem" % target)
        with open(p, "w") as f:
            f.write(priv + "\n")
        os.chmod(p, 0o600)
    except Exception as ke:
        persist_msg = " (私钥本地备份失败: %s)" % ke
    return {"ok": True, "msg": f"已在 {target.upper()} 生成登录密钥并写入 authorized_keys, 私钥已返回(服务器临时文件已删除)" + persist_msg,
            "priv": priv, "pub": pub}


def ssh_download_key(target):
    """返回某台服务器当前登录私钥(供管理员下载备份)。来源: 面板主机密钥库 host_<target>.pem"""
    if target not in ("entry", "cn"):
        return {"ok": False, "msg": "未知服务器目标"}
    p = os.path.join(HOST_KEY_DIR, "host_%s.pem" % target)
    if not os.path.exists(p):
        return {"ok": False, "msg": "该服务器当前无可下载私钥(可先点\"生成并下载 SSH 密钥\"创建)"}
    try:
        with open(p, "r") as f:
            priv = f.read().strip()
        return {"ok": True, "msg": "%s 当前登录私钥已返回(请离线保管)" % target.upper(),
                "priv": priv, "name": "host_%s.pem" % target}
    except Exception as e:
        return {"ok": False, "msg": "读取私钥失败: %s" % e}


def _deploy_panel_key(target, pubkey):
    script = f'''mkdir -p /root/.ssh; chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
grep -qxF '{pubkey}' /root/.ssh/authorized_keys || echo '{pubkey}' >> /root/.ssh/authorized_keys
echo DEPLOYED
'''
    rc, out, err = ssh_exec(target, script, timeout=30)
    return rc == 0 and "DEPLOYED" in out


def _verify_key_login(target):
    """验证面板管理密钥能否登录目标(强制公钥认证, 排除密码回退)"""
    kind, ex = resolve_target(target)
    if kind == "entry":
        port = load_state().get("cn_ssh_port", 22)
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "PreferredAuthentications=publickey",
             "-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=8", "-i", PANEL_KEY,
             "-p", str(port), "root@127.0.0.1", "echo KEYOK"],
            capture_output=True, text=True, timeout=20)
        return proc.returncode == 0 and "KEYOK" in proc.stdout
    if kind == "exit" and ex:
        host = ex["address"]; user = ex.get("ssh_user", "root"); port = ex.get("ssh_port", 22)
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "PreferredAuthentications=publickey",
             "-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=8", "-i", PANEL_KEY,
             "-p", str(port), f"{user}@{host}", "echo KEYOK"],
            capture_output=True, text=True, timeout=20)
        return proc.returncode == 0 and "KEYOK" in proc.stdout
    return False


def _probe_password_login(target):
    """探测目标是否仍接受密码登录(仅用于验证 key-only 是否生效; 入口无密码无法探测)"""
    kind, ex = resolve_target(target)
    if kind == "exit" and ex:
        host = ex["address"]; user = ex.get("ssh_user", "root"); pw = ex.get("ssh_pass", "")
        port = ex.get("ssh_port", 22)
        env = dict(os.environ); env["SSHPASS"] = pw
        args = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                "-o", "ConnectTimeout=8", "-p", str(port), f"{user}@{host}", "echo PWOK"]
        try:
            proc = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            return proc.returncode == 0 and "PWOK" in proc.stdout
        except Exception:
            return False
    return False


def _set_password(target, enable):
    script = f'''CFG=/etc/ssh/sshd_config
cp -f $CFG ${{CFG}}.bak.$(date +%s)
sed -i -E '/^[[:space:]]*#?PasswordAuthentication[[:space:]]+/d' $CFG
echo "PasswordAuthentication {'no' if enable else 'yes'}" >> $CFG
sshd -t && echo CFG_OK || {{ echo CFG_FAIL; exit 1; }}
setsid bash -c 'sleep 2; systemctl restart ssh' >/dev/null 2>&1 < /dev/null &
echo RESTART_SCHEDULED
'''
    rc, out, err = ssh_exec(target, script, timeout=60)
    return rc == 0 and "CFG_OK" in out


def ssh_set_keyonly(target, enable):
    """设置仅密钥登录: 启用前自动部署面板管理密钥并验证, 失败则回滚, 绝不锁死"""
    kind, ex = resolve_target(target)
    if kind is None:
        return {"ok": False, "msg": "未知服务器目标"}
    if enable:
        ensure_panel_key()
        pk = panel_pubkey()
        if not pk:
            return {"ok": False, "msg": "面板管理密钥生成失败"}
        if not _deploy_panel_key(target, pk):
            return {"ok": False, "msg": "无法将面板管理密钥部署到目标, 放弃以免锁死面板自身管理"}
        if not _verify_key_login(target):
            return {"ok": False, "msg": "面板管理密钥登录验证失败, 放弃禁用密码(避免锁死)"}
    if not _set_password(target, enable):
        return {"ok": False, "msg": "sshd 配置校验失败, 未改动(避免锁死)"}
    time.sleep(4)
    if enable:
        if not _verify_key_login(target):
            _set_password(target, True)
            return {"ok": False, "msg": "密钥登录验证失败, 已回滚为允许密码登录"}
        if _probe_password_login(target):
            _set_password(target, True)
            return {"ok": False, "msg": "密码登录仍可用(配置未生效), 已回滚为允许密码登录"}
        return {"ok": True, "msg": "已启用仅密钥登录, 密码登录已禁用; 面板仍可用管理密钥继续管理该服务器"}
    else:
        if not _probe_password_login(target):
            return {"ok": False, "msg": "恢复密码登录似乎未生效, 请检查 sshd 状态"}
        return {"ok": True, "msg": "已恢复允许密码登录"}


# ---- SSH 暴力破解防护 (fail2ban) ----
def ssh_brute_status(target):
    """查询 fail2ban sshd 防护状态与被封 IP 列表"""
    script = r'''
if command -v fail2ban-client >/dev/null 2>&1; then
  act=$(systemctl is-active fail2ban 2>/dev/null || echo unknown)
  if fail2ban-client status sshd >/dev/null 2>&1; then jail=on; else jail=off; fi
  banned=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Banned IP list:/{print $2}' | tr -d ' ')
  banned=${banned:-NONE}
  echo "F2B=yes ACT=$act JAIL=$jail BANNED=$banned"
  grep -rhE "^(maxretry|findtime|bantime|port)[[:space:]]*=" /etc/fail2ban/jail.d/ /etc/fail2ban/jail.local 2>/dev/null | sed 's/[[:space:]]*=[[:space:]]*/=/' | sed 's/^/CFG_/'
else
  echo "F2B=no"
fi
'''
    rc, out, err = ssh_exec(target, script, timeout=40)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "执行失败")}
    d = {"ok": True, "installed": False}
    for line in out.strip().splitlines():
        if line.startswith("CFG_"):
            kv = line[4:]
            if "=" in kv:
                k, v = kv.split("=", 1); d[k] = v
        else:
            for tok in line.split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    if k in ("F2B", "ACT", "JAIL", "BANNED"):
                        d[k] = v
    d["installed"] = d.get("F2B") == "yes"
    d["active"] = d.get("ACT") == "active"
    d["jail_on"] = d.get("JAIL") == "on"
    raw = (d.get("BANNED", "") or "").strip()
    d["banned"] = [] if raw in ("", "NONE") else [x for x in raw.split() if x]
    import re as _re
    cfg = out
    m = _re.search(r"CFG_maxretry=(\d+)", cfg); d["maxretry"] = int(m.group(1)) if m else None
    m = _re.search(r"CFG_findtime=(\d+)", cfg); d["findtime"] = int(m.group(1)) if m else None
    m = _re.search(r"CFG_bantime=(\d+)", cfg); d["bantime"] = int(m.group(1)) if m else None
    m = _re.search(r"CFG_port=(\d+)", cfg); d["port"] = int(m.group(1)) if m else None
    return d


def ssh_brute_set(target, enable):
    """安装/配置/启停 fail2ban 防护 SSH 暴力破解。规则使用面板可配置的全局参数, 端口=实际SSH端口"""
    if enable:
        script = (r'''
export DEBIAN_FRONTEND=noninteractive
PORT=$(grep -iE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config | head -1 | awk '{print $2}')
[ -z "$PORT" ] && PORT=22
command -v fail2ban-client >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq fail2ban) >/dev/null 2>&1
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd-cfui.local <<EOF
[sshd]
enabled = true
port = $PORT
filter = sshd
backend = systemd
maxretry = %d
findtime = %d
bantime = %d
EOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1
sleep 3
act=$(systemctl is-active fail2ban 2>/dev/null)
jail=$(fail2ban-client status sshd >/dev/null 2>&1 && echo on || echo off)
echo "RESULT act=$act jail=$jail port=$PORT"
''') % (BRUTE_MAXFAIL, BRUTE_WINDOW, BRUTE_BAN)
    else:
        script = r'''
fail2ban-client set sshd unbanip --all >/dev/null 2>&1
systemctl stop fail2ban >/dev/null 2>&1
systemctl disable fail2ban >/dev/null 2>&1
echo "RESULT stopped"
'''
    rc, out, err = ssh_exec(target, script, timeout=240)
    if rc != 0:
        return {"ok": False, "msg": (err.strip() or "执行失败"), "raw": out}
    return {"ok": True, "msg": out.strip()}


def ssh_ban_unban(target, ip):
    """fail2ban 解封某 SSH 被封 IP"""
    if not ip:
        return {"ok": False, "msg": "缺少 ip"}
    rc, out, err = ssh_exec(target, "fail2ban-client set sshd unbanip %s 2>&1" % ip, timeout=30)
    return {"ok": rc == 0, "msg": (out.strip() or err.strip() or "done")}


def build_xray_config(state):
    """根据 state 生成入口的 xray config.json, 返回 (cfg, orphan_ports)"""
    exit_tags = {ex["tag"] for ex in state["exits"]}
    inbounds = []
    for ib in state["inbounds"]:
        ss = {"network": "tcp"}
        sec = ib.get("security", "none")
        if sec == "reality":
            r = ib.get("reality") or {}
            sn = r.get("serverName") or (r.get("dest") or "www.apple.com:443").split(":")[0] or "www.apple.com"
            sid = r.get("shortId") or ((r.get("shortIds") or [""])[0] if r.get("shortIds") else "") or ""
            ss["security"] = "reality"
            ss["realitySettings"] = {
                "dest": r.get("dest") or (sn + ":443"),
                "serverNames": [sn],
                "privateKey": r.get("privateKey", ""),
                "shortIds": [sid],
            }
        elif sec == "tls":
            cert, key = ensure_cn_cert()
            ss["security"] = "tls"
            ss["tlsSettings"] = {"certificates": [{"certificateFile": cert, "keyFile": key}]}
        else:
            ss["security"] = "none"
        inbounds.append({
            "port": int(ib["port"]),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "tag": ib["tag"],
            "settings": {"clients": [{"id": state["client_uuid"]}], "decryption": "none"},
            "streamSettings": ss,
            "sniffing": {"enabled": False},
        })
    outbounds = []
    for ex in state["exits"]:
        osec = ex.get("relay_security", "tls")
        oss = {"network": "tcp"}
        if osec == "tls":
            oss["security"] = "tls"
            oss["tlsSettings"] = {"insecure": True}
        else:
            oss["security"] = "none"
        outbounds.append({
            "protocol": "vless",
            "tag": ex["tag"],
            "settings": {
                "vnext": [{
                    "address": ex["address"],
                    "port": int(ex["port"]),
                    "users": [{"id": ex["uuid"], "encryption": "none"}]
                }]
            },
            "streamSettings": oss,
        })
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    rules = []
    orphan = []
    for ib in state["inbounds"]:
        if ib["exit"] in exit_tags:
            rules.append({"type": "field", "inboundTag": ib["tag"], "outboundTag": ib["exit"]})
        else:
            orphan.append(ib["port"])

    # 用户自定义智能分流规则(按域名/IP/端口), 优先级高于按入口端口
    need_block = False
    has_ip_rule = False
    user_rules = []
    if state.get("smart_routing") and state.get("routing_rules"):
        valid_out = exit_tags | {"direct", "block"}
        for r in state["routing_rules"]:
            if not r.get("enabled", True):
                continue
            rt = r.get("type"); rv = (r.get("value") or "").strip(); ob = r.get("outbound")
            if not rt or not rv or ob not in valid_out:
                continue
            rule = {"type": "field", "outboundTag": ob}
            if rt == "domain_suffix":
                rule["domain"] = ["domain:" + rv]
            elif rt == "domain_full":
                rule["domain"] = ["full:" + rv]
            elif rt == "keyword":
                rule["domain"] = ["keyword:" + rv]
            elif rt == "ip":
                rule["ip"] = [rv]; has_ip_rule = True
            elif rt == "geoip":
                rule["ip"] = ["geoip:" + rv]; has_ip_rule = True
            elif rt == "port":
                rule["port"] = rv
            else:
                continue
            user_rules.append(rule)
            if ob == "block":
                need_block = True
    if need_block and not any(o.get("tag") == "block" for o in outbounds):
        outbounds.append({"protocol": "blackhole", "tag": "block"})
    # 智能规则插入到按端口规则之前(优先级更高)
    rules = user_rules + rules

    # 兜底: 未匹配任何入口规则的流量走直连, 避免误路由到首个出口
    rules.append({"type": "field", "ip": ["0.0.0.0/0", "::/0"], "outboundTag": "direct"})
    # 含 IP/GeoIP 规则时需先解析域名才能匹配; 纯域名规则保持 AsIs 以降低延迟
    domain_strategy = "IPIfNonMatch" if has_ip_rule else "AsIs"
    return {
        "log": {"loglevel": "info"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": domain_strategy, "rules": rules},
    }, orphan


def apply_config(state, backup=True):
    """生成配置并应用: 先推送变更的出口, 再写入口配置并重启。返回 (ok, msg)"""
    for ex in state["exits"]:
        rs = ex.get("relay_security", "tls")
        if ex.get("pushed_relay") != rs:
            pw = ex.get("ssh_pass", "")
            if not pw and not os.path.exists(PANEL_KEY):
                return False, (f"出口 {ex['name']} 需推送 {rs} 配置但缺少 SSH 密码且面板管理密钥不可用, "
                               f"请在该出口节点设置 SSH 凭据或确保面板管理密钥存在后再应用")
            ok, log = push_exit_config(ex, pw, ex.get("ssh_user", "root"), ex.get("ssh_port", 22), key=ex.get("ssh_key"))
            if not ok:
                return False, f"推送出口 {ex['name']} 配置失败: {log}"
            ex["pushed_relay"] = rs
    save_state(state)

    cfg, orphan = build_xray_config(state)
    note = f" (警告: 端口 {orphan} 指向的出口不存在, 已跳过规则)" if orphan else ""
    try:
        json.dumps(cfg)
    except Exception as e:
        return False, f"配置生成失败: {e}"
    if backup and os.path.exists(XRAY_CONFIG):
        subprocess.run(["cp", XRAY_CONFIG, XRAY_CONFIG + ".bak"], check=False)
    with open(XRAY_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    r = subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, text=True)
    if r.returncode != 0:
        bak = XRAY_CONFIG + ".bak"
        if os.path.exists(bak):
            subprocess.run(["cp", bak, XRAY_CONFIG], check=False)
            subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, text=True)
        return False, f"重启 xray 失败, 已回滚: {r.stderr}"
    # Type=simple 下 restart 返回 0 不代表进程存活, 必须校验 is-active
    time.sleep(1.5)
    st = subprocess.run(["systemctl", "is-active", SERVICE], capture_output=True, text=True)
    if st.stdout.strip() != "active":
        bak = XRAY_CONFIG + ".bak"
        if os.path.exists(bak):
            subprocess.run(["cp", bak, XRAY_CONFIG], check=False)
            subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, text=True)
        return False, "xray 启动后未进入 active (可能被路由规则/证书拖崩), 已回滚到上次可用配置"
    return True, "配置已应用, xray 已重启 (含中继TLS/入口加密)" + note


# ------------------------------------------------------------------- 备份 / 恢复
def _ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def _collect_backup():
    """收集当前全量设置: state.json + 当前 xray 配置快照"""
    st = load_state()
    xray_cfg = {}
    try:
        with open(XRAY_CONFIG) as f:
            xray_cfg = json.load(f)
    except Exception:
        xray_cfg = {}
    return {
        "meta": {
            "version": 2,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "host": CN_ADDR,
            "note": "x-cfui 全量备份 (state + xray config)",
        },
        "state": st,
        "xray_config": xray_cfg,
    }


def _validate_backup(data):
    if not isinstance(data, dict):
        return False, "备份格式错误 (非 JSON 对象)"
    if "state" not in data or not isinstance(data["state"], dict):
        return False, "备份缺少 state 字段"
    st = data["state"]
    for k in ("inbounds", "exits"):
        if k not in st:
            return False, "state 缺少必要字段: " + k
    return True, ""


def _apply_backup(data):
    """恢复备份: 写回 state 并重新生成/应用 xray 配置。返回 (ok, msg)"""
    ok, msg = _validate_backup(data)
    if not ok:
        return False, msg
    st = data["state"]
    save_state(st)
    return apply_config(st, backup=True)


# 出厂默认设置 = 可移植“模板”，剔除一切服务器身份与凭据字段
# (IP / 端口 / 密码 / 密钥 / 入口口令 / 客户端UUID 等)，
# 因为其他服务器或未来的服务器这些信息完全不同，绝不能带入模板。
TEMPLATE_FIELDS = ("routing_rules", "smart_routing", "site_title", "site_footer")


def _build_template():
    """仅收集可移植的通用设置，剔除全部服务器身份/凭据信息。"""
    st = load_state()
    subset = {k: st.get(k) for k in TEMPLATE_FIELDS}
    return {
        "meta": {
            "version": 3,
            "template": True,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "x-cfui 出厂默认设置模板 (仅含可移植设置: 路由规则/智能路由/"
                    "站点标题/页脚；不含任何服务器 IP/端口/密码/密钥/凭据)",
        },
        "state": subset,
    }


def _apply_template(obj):
    """把出厂默认模板合并进当前设置: 仅写入可移植字段，
    完整保留本机的 IP/端口/密码/密钥/凭据等身份字段。"""
    live = load_state()
    sub = obj.get("state", {})
    if not isinstance(sub, dict):
        return False, "模板 state 格式错误"
    for k in TEMPLATE_FIELDS:
        if k in sub:
            live[k] = sub[k]
    save_state(live)
    return apply_config(live, backup=True)


# ------------------------------------------------------------------- HTML
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title id="page_title">x-cfui</title>
<style>
:root{
  --bg:#0f1115;--card:#1a1d24;--acc:#4f8cff;--ok:#3fb950;--err:#f85149;--txt:#e6edf3;
  --mut:#8b949e;--border:#262b33;--input:#0d1117;--code:#0d1117;
  --tag-bg:#21262d;--btn-sec:#30363d;
}
:root[data-theme="light"]{
  --bg:#f4f6f9;--card:#ffffff;--acc:#2563eb;--ok:#1a7f37;--err:#cf222e;--txt:#1f2328;
  --mut:#57606a;--border:#d0d7de;--input:#ffffff;--code:#f0f2f5;
  --tag-bg:#eaeef2;--btn-sec:#e3e8ee;
}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);padding:20px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:18px 0 10px;color:var(--acc)}
.sub{color:var(--mut);font-size:12px;margin-bottom:14px}
.card{background:var(--card);border-radius:10px;padding:16px;margin-bottom:14px;border:1px solid var(--border)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:6px 0}
input,select{background:var(--input);border:1px solid var(--border);color:var(--txt);padding:8px 10px;border-radius:6px;font-size:13px;min-width:120px}
button{background:var(--acc);color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px}
button.sec{background:var(--btn-sec);color:var(--txt)}button.danger{background:var(--err)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
.tag{background:var(--tag-bg);padding:2px 8px;border-radius:4px;font-size:12px;color:var(--mut)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px}
.ok{background:rgba(63,185,80,.15);color:var(--ok)}.err{background:rgba(248,81,73,.15);color:var(--err)}
.warn{background:rgba(210,153,34,.15);color:#d29922}
.enc{background:rgba(79,140,255,.15);color:var(--acc)}
.yes{background:rgba(63,185,80,.15);color:var(--ok)}.no{background:rgba(248,81,73,.15);color:var(--err)}
#status{font-size:13px;padding:10px;border-radius:6px;margin-top:8px;display:none}
#status.ok{background:rgba(63,185,80,.1);color:var(--ok);display:block}
#status.err{background:rgba(248,81,73,.1);color:var(--err);display:block}
a.link{color:var(--acc);cursor:pointer;font-size:12px;margin-right:8px}
.node-name{cursor:pointer;border-bottom:1px dashed var(--acc);padding-bottom:1px}
.node-name:hover{color:var(--acc)}
.code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--code);padding:8px;border-radius:6px;word-break:break-all;border:1px solid var(--border)}
.copybtn{background:var(--btn-sec);color:var(--txt);padding:4px 8px;font-size:11px}
.okline{color:var(--ok);font-weight:600;display:block;margin:4px 0;font-size:14px}
.warnline{color:var(--err);font-weight:600;display:block;margin:4px 0;font-size:14px}
.topbar{display:flex;gap:10px;align-items:center;margin-bottom:14px}
.brand{font-size:18px;font-weight:600;color:var(--acc)}
.topbar .spacer{flex:1}
pre.out{background:var(--code);padding:10px;border-radius:6px;font-size:12px;white-space:pre-wrap;max-height:240px;overflow:auto;border:1px solid var(--border)}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
.footer{text-align:center;color:var(--mut);font-size:12px;margin-top:24px;padding-top:14px;border-top:1px solid var(--border)}
details{margin:4px 0}summary{cursor:pointer;color:var(--mut);font-size:12px}
.card > h2{cursor:pointer;display:flex;align-items:center;gap:6px;user-select:none;padding:4px 0;border-radius:6px;transition:background .15s}
.card > h2:hover{background:rgba(127,127,127,.14)}
.card > h2 .ctoggle{font-size:15px;line-height:1;color:var(--acc);transition:transform .15s ease;flex:0 0 auto;font-weight:700}
.card.collapsed > h2 .ctoggle{transform:rotate(-90deg)}
.card > h2 .ctext{font-size:12px;color:var(--mut);font-weight:600;margin-left:2px}
.card.collapsed > *:not(h2){display:none!important}
.nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:50;border-bottom:1px solid var(--border)}
.navbtn{cursor:pointer;padding:8px 14px;border-radius:8px;border:1px solid var(--border);background:var(--code);color:var(--txt);font-size:14px;font-weight:600;transition:.15s}
.navbtn:hover{background:rgba(127,127,127,.14)}
.navbtn.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.section{display:none}
.section.active{display:block}
</style>
</head>
<body>
<div class="topbar">
  <span class="brand">x-cfui</span>
  <span class="spacer"></span>
  <button class="sec" id="themeBtn" onclick="toggleTheme()">主题: 夜间</button>
  <button class="sec" id="langBtn" onclick="toggleLang()">EN</button>
</div>

<div class="nav">
  <button class="navbtn active" data-nav="nodes" data-i18n="navNodes" onclick="switchNav('nodes')">节点管理</button>
  <button class="navbtn" data-nav="routing" data-i18n="navRouting" onclick="switchNav('routing')">分流设置</button>
  <button class="navbtn" data-nav="client" data-i18n="navClient" onclick="switchNav('client')">客户端设置</button>
  <button class="navbtn" data-nav="site" data-i18n="navSite" onclick="switchNav('site')">网站设置</button>
  <button class="navbtn" data-nav="security" data-i18n="navSecurity" onclick="switchNav('security')">安全设置</button>
  <button class="navbtn" data-nav="ops" data-i18n="navOps" onclick="switchNav('ops')">系统运维</button>
  <button class="navbtn" data-nav="account" data-i18n="navAccount" onclick="switchNav('account')">账户中心</button>
</div>

<div class="section active" data-nav="nodes">
<div class="card">
  <div class="card">
    <h2 data-i18n="bbrTitle">BBR 状态验证</h2>
    <div class="sub" data-i18n="bbrSub">BBR 是 TCP 拥塞控制算法。下方「验证入口 BBR」检测本机入口服务器; 每个出口节点表格内有独立「验证BBR」按钮。</div>
    <div id="bbrStatus" class="tag">未检测</div>
    <div class="row" style="margin-top:8px"><button onclick="checkBbr()" data-i18n="bbrBtn">验证入口 BBR</button></div>
  </div>

  <h2 data-i18n="exitTitle">① 出口节点</h2>
  <table id="exitTable"><thead><tr><th data-i18n="thName">名称</th><th data-i18n="thAddr">地址</th><th data-i18n="thPort">端口</th><th>UUID</th><th data-i18n="thRelay">中继加密</th><th>BBR</th><th data-i18n="thOp">操作</th></tr></thead><tbody></tbody></table>
  <div class="row" style="margin-top:10px">
    <input id="ex_name" data-i18n-ph="phExitName" placeholder="出口名称(如HK节点)">
    <input id="ex_addr" placeholder="出口服务器IP">
    <input id="ex_uuid" placeholder="UUID(留空自动生成)">
    <button onclick="addExit()" data-i18n="btnAddExit">+ 添加出口节点</button>
  </div>
  <div class="row"><span class="tag" data-i18n="exitHint">提示: 添加的出口默认启用「中继TLS加密」与「BBR」。SSH 密码在 ③ 部署时记录。</span></div>
</div>
</div>

<div class="section" data-nav="routing">
<div class="card">
  <h2 data-i18n="inTitle">② 入口端口</h2>
  <table id="inTable"><thead><tr><th data-i18n="thPort">端口</th><th data-i18n="thName">名称</th><th data-i18n="thExit">分流到出口</th><th data-i18n="thSec">加密方式</th><th>UUID</th><th data-i18n="thOp">操作</th></tr></thead><tbody></tbody></table>
  <div class="row" style="margin-top:10px">
    <input id="in_port" placeholder="新入口端口号(如8443)" type="number">
    <input id="in_name" placeholder="线路名称(如俄线)">
    <select id="in_exit"></select>
    <select id="in_sec">
      <option value="reality" data-i18n="secReality">Reality 伪装(推荐)</option>
      <option value="tls" data-i18n="secTls">TLS 证书</option>
      <option value="none" data-i18n="secNone">无加密</option>
    </select>
    <input id="in_sni" placeholder="伪装域名(Reality用, 可空)" style="min-width:180px">
    <button onclick="addInbound()" data-i18n="btnAddIn">+ 添加入口端口</button>
  </div>
  <div class="row">
    <span class="tag" data-i18n="uuidTag">全局客户端UUID (所有入口共用)</span>
    <input id="client_uuid" style="min-width:340px">
    <button class="sec" onclick="saveClientUuid()" data-i18n="btnSaveUuid">保存UUID</button>
  </div>
</div>
</div>

<div class="section" data-nav="nodes">
<div class="card">
  <h2 data-i18n="provTitle">③ 一键部署新出口服务器 (自动装Xray + TLS + BBR)</h2>
  <div class="sub" data-i18n="provSub">填好信息点按钮, 面板自动: 加入出口节点(默认10443/TLS/BBR) → SSH 装 Xray 并接收入口中继 → 记录 SSH 凭据。</div>
  <div class="row">
    <input id="prov_name" data-i18n-ph="phExitName" placeholder="出口名称(如HK节点)" style="min-width:140px">
    <input id="prov_addr" placeholder="服务器IP地址" style="min-width:180px">
    <input id="prov_user" placeholder="SSH用户名" value="root" style="min-width:120px">
    <input id="prov_pass" type="password" placeholder="SSH密码">
    <input id="prov_sshport" placeholder="SSH端口" type="number" value="22" style="min-width:90px">
    <select id="prov_ssh_key"><option value="">SSH密钥: 默认(面板密钥/密码)</option></select>
    <button onclick="provisionExit()" data-i18n="btnProv">添加并部署</button>
  </div>
  <pre id="prov_log" class="out" style="display:none"></pre>
</div>
</div>

<div class="section" data-nav="security">
<div class="card">
  <h2 data-i18n="fwTitle">防火墙管理 (开关 / 端口放行 / 禁止)</h2>
  <div class="sub" data-i18n="fwSub">可管理入口与各出口的防火墙。启用前会自动放行 SSH(22)/面板(5000)/代理端口，避免锁死。基于 ufw。</div>
  <div class="row">
    <select id="fw_target" onchange="fwStatus()"></select>
    <button onclick="fwToggle('enable')" data-i18n="fwEnable">启用防火墙</button>
    <button class="danger" onclick="fwToggle('disable')" data-i18n="fwDisable">禁用防火墙</button>
    <button class="sec" onclick="fwStatus()" data-i18n="fwRefresh">刷新状态</button>
  </div>
  <div class="row">
    <input id="fw_port" placeholder="端口(如 8080)" type="number" style="min-width:120px">
    <select id="fw_proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
    <select id="fw_rule"><option value="allow" data-i18n="fwAllow">放行</option><option value="deny" data-i18n="fwDeny">禁止</option></select>
    <button onclick="fwRule()" data-i18n="fwApply">应用规则</button>
  </div>
  <div id="fw_info" class="tag" style="margin-top:6px">未查询</div>
  <pre id="fw_out" class="out" style="display:none"></pre>
</div>
</div>

<div class="section" data-nav="ops">
<div class="card">
  <h2 data-i18n="asTitle">开机自启核验</h2>
  <div class="sub" data-i18n="asSub">逐项验证每台服务器的 Xray / BBR / 防火墙 是否开机自动启动。本架构不使用 DNAT 端口转发，分流由 Xray 内部路由完成。</div>
  <div class="row"><button onclick="verifyAll()" data-i18n="asVerifyAll">全部验证</button></div>
  <div id="as_list"></div>
</div>
</div>

<div class="section" data-nav="client">
<div class="card">
  <h2 data-i18n="linkTitle">④ 客户端连接 (加密状态 / 伪装信息 / 订阅)</h2>
  <div class="sub" data-i18n="linkSub">每个入口端口的客户端连接字符串。Reality 模式自带 TLS 级加密与真实网站伪装。</div>
  <div class="row">
    <span data-i18n="fpLabel">客户端伪装指纹</span>
    <select id="client_fp">
      <option value="chrome">Chrome</option>
      <option value="firefox">Firefox</option>
      <option value="safari">Safari</option>
      <option value="edge">Edge</option>
      <option value="ios">iOS</option>
      <option value="android">Android</option>
      <option value="random">Random</option>
    </select>
    <button class="sec" onclick="saveFp()" data-i18n="fpSave">保存伪装</button>
  </div>
  <div class="sub" data-i18n="fpHint">说明：客户端连接入口服务器时伪装的 TLS 指纹。所有入口端口(443/8443等)共用此设置，出口服务器仅中转不受影响。</div>
  <div class="row">
    <span data-i18n="phHost">对外域名/地址</span>
    <input id="public_host_input" style="width:220px" placeholder="如 wdjs.ad2312a3d.xyz">
    <button class="sec" onclick="addHost()" data-i18n="hostAdd">添加地址</button>
  </div>
  <div id="hosts_list" style="margin-top:6px"></div>
  <div class="sub" data-i18n="hostHint">客户端链接与二维码将使用此地址连接入口服务器。请确保该域名已解析到入口服务器。可添加多个地址，链接表格会为每个地址生成独立的连接串。</div>
  <table id="linkTable"><thead><tr><th data-i18n="thPortName">端口/名称</th><th data-i18n="thSec">加密</th><th data-i18n="thLink">客户端链接 (点击复制)</th></tr></thead><tbody></tbody></table>
</div>
</div>

<div class="section" data-nav="site">
<div class="card">
  <h2 data-i18n="siteSetTitle">网站标题与页脚设置</h2>
  <div class="sub" data-i18n="siteSetSub">自定义面板浏览器标签页标题与底部页脚文字。</div>
  <div class="row">
    <span data-i18n="siteTitleLabel">网站标题</span>
    <input id="site_title_input" style="width:260px" placeholder="如 Xray 管理面板" value="">
    <span data-i18n="siteFooterLabel">页脚文字</span>
    <input id="site_footer_input" style="width:220px" placeholder="如 &copy; 2025 MyPanel" value="">
    <button class="sec" onclick="saveSiteSettings()" data-i18n="siteSetSave">保存网站设置</button>
  </div>
  <div id="site_settings_msg" class="tag"></div>
</div>
</div>

<div class="section" data-nav="nodes">
<div class="card">
  <h2 data-i18n="applyTitle">⑤ 应用 / 状态</h2>
  <div class="row">
    <button onclick="applyConfig()" data-i18n="btnApply">应用配置并重启 Xray</button>
    <button class="sec" onclick="loadState()" data-i18n="btnRefresh">刷新</button>
    <span id="xray_stat"></span>
  </div>
  <div id="toast" style="display:none;position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:9999;padding:10px 24px;border-radius:8px;font-size:14px;font-weight:600;box-shadow:0 4px 20px rgba(0,0,0,.4);transition:opacity .3s;max-width:90vw;word-break:break-word;text-align:center"></div>
</div>
</div>

<div class="section" data-nav="account">
<div class="card">
  <h2 data-i18n="secTitle">⑥ 账号与安全</h2>
  <div class="sub" data-i18n="secSub">修改后台登录账号 / 密码, 以及面板的安全入口密令 (改后需重新登录)。</div>
  <div class="row">
    <input id="sec_user" placeholder="登录账号" style="min-width:140px">
    <input id="sec_pass" type="password" placeholder="新密码(留空不改)">
    <input id="sec_pass2" type="password" placeholder="确认新密码">
    <input id="sec_token" placeholder="入口密令 如 aa888888" style="min-width:160px">
    <button onclick="saveSecurity()" data-i18n="btnSaveSec">保存安全设置</button>
  </div>
  <div class="row"><span class="tag" id="sec_hint"></span></div>
</div>
</div>

<div class="section" data-nav="security">
<div class="card">
  <h2 data-i18n="sshTitle">⑦ SSH 安全加固 (端口 / 密钥 / 仅密钥登录)</h2>
  <div class="sub" data-i18n="sshSub">管理三台服务器的 SSH：修改端口、生成登录密钥、设置为仅密钥登录；并可在密钥库管理用于连接新出口的私钥。</div>
  <div class="row">
    <span data-i18n="thTarget">目标服务器</span>
    <select id="ssh_target" onchange="sshStatus()">
      <option value="entry">入口服务器</option>
    </select>
    <button class="sec" onclick="sshStatus()" data-i18n="sshRefresh">刷新状态</button>
  </div>
  <div class="row"><span id="ssh_info" class="tag"></span></div>
  <div class="row">
    <input id="ssh_port" placeholder="新SSH端口(1-65535)" style="min-width:170px">
    <button onclick="sshSetPort()" data-i18n="sshSetPort">修改 SSH 端口</button>
  </div>
  <div class="row">
    <button onclick="sshGenKey()" data-i18n="sshGenKey">生成并下载 SSH 密钥</button>
    <button onclick="sshDownloadCurrent()" data-i18n="sshDownloadCurrent">下载当前密钥</button>
    <button onclick="sshKeyOnly(true)" data-i18n="sshEnableKeyOnly">启用仅密钥登录</button>
    <button class="sec" onclick="sshKeyOnly(false)" data-i18n="sshDisableKeyOnly">恢复密码登录</button>
  </div>
  <div id="ssh_keybox" style="display:none">
    <textarea id="ssh_priv" rows="4" style="width:100%;font-family:monospace" readonly placeholder="私钥"></textarea>
    <div class="row">
      <button onclick="sshDownloadKey()" data-i18n="sshDownload">下载私钥</button>
      <button class="sec" onclick="copyText('ssh_priv')" data-i18n="sshCopy">复制私钥</button>
    </div>
  </div>
  <pre id="ssh_out" class="out" style="display:none"></pre>

  <h3 data-i18n="sshVaultTitle">SSH 密钥库 (连接新出口用)</h3>
  <div class="sub" data-i18n="sshVaultSub">上传私钥(权限600)供新出口选择使用；可删除释放磁盘。仅存文件名，私钥不对外展示。</div>
  <div class="row">
    <input id="ssh_key_name" placeholder="密钥文件名(如 sg_root.pem)" style="min-width:170px">
    <input id="ssh_key_file" type="file" accept=".pem,.key,*,*" style="min-width:200px">
    <button onclick="sshUploadKey()" data-i18n="sshUpload">上传密钥</button>
  </div>
  <div id="ssh_keys_list" class="row" style="flex-direction:column;align-items:flex-start"></div>
</div>
</div>

<div class="section" data-nav="security">
<div class="card">
  <h2 data-i18n="bruteTitle">暴力破解防护</h2>
  <div class="sub" data-i18n="bruteSub">面板登录与 SSH 登录的暴力破解防护</div>
  <div class="warnline" data-i18n="bruteRule" style="margin:6px 0">规则</div>

  <h3 data-i18n="bruteCfgTitle">防护参数配置 (可修改)</h3>
  <div class="row">
    <label style="display:flex;flex-direction:column;gap:2px;font-size:13px"><span data-i18n="bruteWindow">统计窗口(秒)</span><input id="brute_window" type="number" min="1" max="3600" style="width:90px"></label>
    <label style="display:flex;flex-direction:column;gap:2px;font-size:13px"><span data-i18n="bruteMaxfail">窗口内最大失败次数</span><input id="brute_maxfail" type="number" min="1" max="1000" style="width:90px"></label>
    <label style="display:flex;flex-direction:column;gap:2px;font-size:13px"><span data-i18n="bruteBan">封锁时长(秒)</span><input id="brute_ban" type="number" min="30" max="31536000" style="width:120px"></label>
    <button class="sec" onclick="bruteCfgSave()" data-i18n="bruteCfgSave">保存参数</button>
  </div>
  <div id="brute_cfg_current" class="row" style="color:#888;font-size:13px"></div>
  <div id="brute_cfg_msg" class="row"></div>

  <h3 data-i18n="brutePanel">面板登录防护 (应用层)</h3>
  <div class="row">
    <span id="brute_panel_info" class="tag">未查询</span>
    <button class="sec" onclick="brutePanelList()" data-i18n="bruteRefreshBans">刷新封锁列表</button>
  </div>
  <div id="brute_panel_bans" class="row" style="flex-direction:column;align-items:flex-start"></div>

  <h3 data-i18n="bruteSsh">SSH 登录防护 (fail2ban)</h3>
  <div class="row">
    <span data-i18n="bruteTarget">目标服务器</span>
    <select id="brute_ssh_target">
      <option value="entry">入口服务器</option>
    </select>
    <button class="sec" onclick="bruteSshStatus()" data-i18n="bruteRefreshBans">查询状态</button>
    <button class="sec" onclick="bruteSshEnable(true)" data-i18n="bruteEnable">启用 SSH 防护</button>
    <button class="sec" onclick="bruteSshEnable(false)" data-i18n="bruteDisable">停用 SSH 防护</button>
  </div>
  <div id="brute_ssh_info" class="tag" style="margin-top:6px"></div>
  <div id="brute_ssh_bans" class="row" style="flex-direction:column;align-items:flex-start;margin-top:6px"></div>
</div>
</div>

<div class="section" data-nav="routing">
<div class="card">
  <h2 data-i18n="routeTitle">⑧ 智能分流规则</h2>
  <div class="sub" data-i18n="routeSub">按域名 / IP / 端口智能分流, 命中规则优先于"按入口端口"分流。规则从上到下依次匹配, 命中即走所选出口。</div>
  <div class="row">
    <label><input type="checkbox" id="route_enabled" onchange="routeToggle()"> <span data-i18n="routeEnable">启用智能分流</span></label>
    <span id="route_geoip" class="tag"></span>
  </div>
  <div class="row" id="route_box" style="display:none;flex-direction:column;align-items:stretch">
    <div id="route_list" class="row" style="flex-direction:column;align-items:stretch"></div>
    <div class="row">
      <button onclick="routeAdd()" data-i18n="routeAdd">+ 添加规则</button>
      <button onclick="routeSave()" data-i18n="routeApply">保存并应用</button>
      <span id="route_msg"></span>
    </div>
    <div class="sub" data-i18n="routeHint">示例: 类型=域名后缀 值=tiktok.com 出口=hk-out → 所有 TikTok 流量走香港节点; 类型=GeoIP 值=HK 出口=direct → 香港 IP 直连。</div>
  </div>
</div>
</div>

<div class="section" data-nav="ops">
<div class="card">
  <h2 data-i18n="portsTitle">⑨ 端口占用 (每台服务器当前监听的全部端口)</h2>
  <div class="sub" data-i18n="portsSub">实时查询三台服务器的所有监听端口(TCP/UDP), 含地址、协议与进程。SSH / 面板 / Xray 端口会以标签标注。</div>
  <div class="row">
    <button onclick="portsLoad()" data-i18n="portsRefresh">刷新端口</button>
    <span id="ports_time" class="tag"></span>
  </div>
  <div id="ports_box"></div>
  <div class="row" style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
    <button onclick="fwHarden()" data-i18n="fwHardenBtn">一键加固防火墙</button>
    <span id="fw_harden_msg" class="tag"></span>
  </div>
  <div class="sub" data-i18n="fwHardenSub">对三台服务器放行上方展示的全部监听端口, 其余未使用端口全部拒绝 (default deny)。SSH/面板/代理端口均在放行列表中, 不会锁死。</div>
  <pre id="fw_harden_out" style="display:none;white-space:pre-wrap;background:var(--code);padding:10px;border-radius:8px;margin-top:8px;max-height:240px;overflow:auto"></pre>
</div>

<div class="card">
  <h2 data-i18n="backupTitle">⑩ 备份与恢复</h2>
  <div class="sub" data-i18n="backupSub">一键备份当前所有设置 (节点 / 入口端口 / 分流 / 对外域名 / 网站设置 / 安全), 可下载到本地; 也能从本地备份文件恢复。系统会维护一份出厂默认备份。</div>
  <div class="row">
    <button onclick="backupExport()" data-i18n="backupExport">① 一键备份并下载</button>
    <button class="sec" onclick="backupDefaultSave()" data-i18n="backupDefaultSave">④ 保存为出厂默认备份</button>
  </div>
  <div class="row" style="margin-top:10px">
    <input id="backup_file" type="file" accept=".json,application/json" style="min-width:200px">
    <button onclick="backupUpload()" data-i18n="backupUpload">② 上传备份文件</button>
    <button class="sec" onclick="backupRestore()" data-i18n="backupRestore">③ 恢复设置</button>
  </div>
  <div class="row" style="margin-top:10px">
    <button onclick="backupDefaultRestore()" data-i18n="backupDefaultRestore">⑤ 一键导入出厂默认设置</button>
  </div>
  <div id="backup_msg" class="tag" style="margin-top:6px"></div>

  <h3 style="margin-top:12px" data-i18n="backupSavedTitle">已保存的服务器备份</h3>
  <div class="sub" data-i18n="backupSavedSub">每次「一键备份并下载」会自动在此处保留一份服务器副本，可直接下载或恢复，也可删除释放空间。</div>
  <div class="row"><button class="sec" onclick="backupListLoad()" data-i18n="backupSavedRefresh">刷新备份列表</button></div>
  <table class="tbl" style="margin-top:6px">
    <thead><tr>
      <th data-i18n="backupFilename">文件名</th>
      <th data-i18n="machineSize">大小</th>
      <th data-i18n="machineTime">时间</th>
      <th data-i18n="thOp">操作</th>
    </tr></thead>
    <tbody id="backup_saved_list"><tr><td colspan="4" style="color:#888;padding:8px;text-align:center" data-i18n="backupEmpty">暂无已保存备份，点击上方「一键备份并下载」创建</td></tr></tbody>
  </table>
  <div id="backup_saved_msg" class="tag" style="margin-top:6px"></div>

  <div class="sub" data-i18n="backupHint">说明: ①~③ 为整机完整备份 (含服务器 IP/端口/密码/密钥, 仅限本机迁移); ④⑤ 出厂默认备份为“可移植模板”, 刻意剔除所有服务器 IP/端口/密码/密钥/凭据, 仅保留路由规则/智能路由/站点标题/页脚, 可安全用于其他或未来的服务器。恢复前建议先「一键备份并下载」以防丢失。</div>
</div>

<div class="card">
  <h2 data-i18n="machineTitle">⑪ 整机完整备份</h2>
  <div class="sub" data-i18n="machineSub">对指定服务器执行完整文件系统备份 (tar.gz 全量归档, 排除 /proc /sys /dev 等虚拟文件系统), 备份文件存储在目标服务器本地 /opt/x-cfui/machine_backups。可下载到本地或删除。</div>
  <div class="row">
    <select id="machine_target" onchange="machineLoad()">
      <option value="entry">入口(本机)</option>
    </select>
    <button onclick="machineStart()" data-i18n="machineStart">开始整机备份</button>
    <button class="sec" onclick="machineLoad()" data-i18n="machineRefresh">刷新列表</button>
  </div>
  <div class="sub" data-i18n="machineStatus">当前状态</div>
  <div id="machine_status" class="tag"></div>
  <table class="tbl">
    <thead><tr>
      <th data-i18n="machineFilename">文件名</th>
      <th data-i18n="machineSize">大小</th>
      <th data-i18n="machineTime">时间</th>
      <th data-i18n="thOp">操作</th>
    </tr></thead>
    <tbody id="machine_list"></tbody>
  </table>
  <div id="machine_msg" class="tag" style="margin-top:6px"></div>
  <div class="sub" data-i18n="machineWarn">注意: 备份存放在目标服务器本机磁盘, 若磁盘故障将一同丢失; 重要数据请下载到本地或其它机器保管。大磁盘整机备份可能需数分钟。</div>
</div>
</div>

<div class="footer" id="page_footer">QQ: 123008</div>

<script>
const BASE = location.pathname.split('/api/')[0].replace(/\/+$/,'') || '';
let LANG = localStorage.getItem('xc_lang') || 'en';
let THEME = localStorage.getItem('xc_theme') || 'dark';

const I18N = {
  zh: {
    appName:'x-cfui 管理面板', bbrTitle:'BBR 状态验证', bbrSub:'BBR 是 TCP 拥塞控制算法。下方「验证入口 BBR」检测本机入口服务器; 每个出口节点表格内有独立「验证BBR」按钮。',
    bbrBtn:'验证入口 BBR', exitTitle:'① 出口节点', thName:'名称', thAddr:'地址', thPort:'端口', thRelay:'中继加密', thOp:'操作',
    btnAddExit:'+ 添加出口节点', exitHint:'提示: 添加的出口默认启用「中继TLS加密」与「BBR」。SSH 密码在 ③ 部署时记录。',
    inTitle:'② 入口端口', thExit:'分流到出口', thSec:'加密方式', thLink:'客户端链接 (点击复制)', thPortName:'端口/名称',
    btnAddIn:'+ 添加入口端口', uuidTag:'全局客户端UUID (所有入口共用)', btnSaveUuid:'保存UUID',
    provTitle:'③ 一键部署新出口服务器 (自动装Xray + TLS + BBR)', provSub:'填好信息点按钮, 面板自动: 加入出口节点(默认10443/TLS/BBR) → SSH 装 Xray 并接收入口中继 → 记录 SSH 凭据。',
    btnProv:'添加并部署', fwTitle:'防火墙管理 (开关 / 端口放行 / 禁止)', fwSub:'可管理入口与各出口的防火墙。启用前会自动放行 SSH(22)/面板(5000)/代理端口，避免锁死。基于 ufw。',
    fwEnable:'启用防火墙', fwDisable:'禁用防火墙', fwRefresh:'刷新状态', fwAllow:'放行', fwDeny:'禁止', fwApply:'应用规则', fwRule:'防火墙规则',
    fwHardenBtn:'一键加固防火墙', fwHardenSub:'对三台服务器放行上方展示的全部监听端口, 其余未使用端口全部拒绝 (default deny)。SSH/面板/代理端口均在放行列表中, 不会锁死。', fwHardenConfirm:'确认对三台服务器放行所有监听端口, 并拒绝其余端口?', fwHardenOk:'三台防火墙已加固',
    asTitle:'开机自启核验', asSub:'逐项验证每台服务器的 Xray / BBR / 防火墙 是否开机自动启动。本架构不使用 DNAT 端口转发，分流由 Xray 内部路由完成。', asVerifyAll:'全部验证',
    linkTitle:'④ 客户端链接 (加密状态 / 伪装信息 / 订阅)', linkSub:'每个入口端口的客户端连接字符串。Reality 模式自带 TLS 级加密与真实网站伪装。',
    fpLabel:'客户端伪装指纹', fpSave:'保存伪装', fpHint:'说明：客户端连接入口服务器时伪装的 TLS 指纹。所有入口端口(443/8443等)共用此设置，出口服务器仅中转不受影响。',
    phHost:'对外域名/地址', hostSave:'保存地址', hostAdd:'添加地址', hostHint:'客户端链接与二维码将使用此地址连接入口服务器。请确保该域名已解析到 入口服务器。可添加多个地址，链接表格会为每个地址生成独立的连接串。', hostEmpty:'地址不能为空', collapseOpen:'展开', collapseClose:'收起', navNodes:'节点管理', navRouting:'分流设置', navSite:'网站设置', navClient:'客户端设置', navSecurity:'安全设置', navOps:'系统运维', navAccount:'账户中心', applyTitle:'⑤ 应用 / 状态', btnApply:'应用配置并重启 Xray', btnRefresh:'刷新',
    siteSetTitle:'网站设置 (标题 / 页脚)', siteSetSub:'自定义面板的浏览器标签页标题和底部页脚文字。保存后即时生效，无需重启服务。', siteTitleLabel:'网站标题', siteFooterLabel:'页脚文字', siteSetSave:'保存网站设置', siteSavedOk:'网站设置已保存', siteSetEmpty:'标题与页脚不能都为空',
    backupTitle:'⑩ 备份与恢复', backupSub:'一键备份当前所有设置 (节点 / 入口端口 / 分流 / 对外域名 / 网站设置 / 安全), 可下载到本地; 也能从本地备份文件恢复。系统会维护一份出厂默认备份。', backupExport:'① 一键备份并下载', backupDefaultSave:'④ 保存为出厂默认备份', backupUpload:'② 上传备份文件', backupRestore:'③ 恢复设置', backupDefaultRestore:'⑤ 一键导入出厂默认设置', backupHint:'说明: ①~③ 为整机完整备份 (含服务器 IP/端口/密码/密钥, 仅限本机迁移); ④⑤ 出厂默认备份为“可移植模板”, 刻意剔除所有服务器 IP/端口/密码/密钥/凭据, 仅保留路由规则/智能路由/站点标题/页脚, 可安全用于其他或未来的服务器。恢复前建议先「一键备份并下载」以防丢失。', backupNoFile:'请选择备份文件', backupTime:'备份时间 ', backupReady:'已就绪, 可恢复', backupRestored:'已恢复', backupConfirmRestore:'确认用已上传的备份恢复所有设置? 当前设置将被覆盖 (建议先备份)。',     backupConfirmDefault:'将当前"可移植设置"(路由规则/智能路由/站点标题/页脚) 保存为出厂默认模板? 注意: 不会包含任何服务器 IP/端口/密码/密钥, 可安全用在其他服务器。此操作覆盖原有出厂默认。', backupConfirmImport:'确认导入出厂默认模板? 仅导入路由规则/智能路由/站点标题/页脚, 本机 IP/端口/密码/密钥/凭据保持不变。', backupSavedTitle:'已保存的服务器备份', backupSavedSub:'每次「一键备份并下载」会自动在此处保留一份服务器副本，可直接下载或恢复，也可删除释放空间。', backupSavedRefresh:'刷新备份列表', backupEmpty:'暂无已保存备份，点击上方「一键备份并下载」创建', backupFilename:'文件名', backupConfirmDelete:'确认删除此备份? 删除后不可恢复。',
    secTitle:'⑥ 账号与安全', secSub:'修改后台登录账号 / 密码, 以及面板的安全入口密令 (改后需重新登录)。', btnSaveSec:'保存安全设置',
    phExitName:'出口名称(如HK节点)', secReality:'Reality 伪装(推荐)', secTls:'TLS 证书', secNone:'无加密',
    copied:'已复制链接', copyFail:'复制失败, 请手动选择', notActive:'无加密', reality:'Reality伪装', tls:'TLS',
    bbrOn:'已开启', bbrOff:'未开启', relayTls:'TLS加密', relayPlain:'明文',
    yes:'是', no:'否', fwOn:'已启用', fwOff:'未启用', fwNotInst:'未安装',
    del:'删除', openBbr:'开启BBR', verifyBbr:'验证BBR',
    rename:'重命名', clickRename:'点击名称可直接修改', save:'保存', cancel:'取消',
    asXray:'Xray 服务', asBbr:'BBR 拥塞控制', asFw:'防火墙', asPf:'端口转发', asAdmin:'面板服务',
    asAllOk:'全部开机自启正常', asSomeIssue:'存在未开机自启项', verifyOk:'核验完成', needSsh:'缺少 SSH 密码，请在弹窗输入',
    fwInfo:'未查询', fwLoading:'正在查询防火墙状态', themeNight:'主题: 夜间', themeDay:'主题: 白天', bootAuto:'开机自动',
    bbrOk:'BBR 加速正常运行（已开机自启）', bbrOff:'BBR 未生效，当前算法', bbrNoAuto:'BBR 已生效但未设置开机自启（重启会失效，请重新开启）',     bbrCheckFail:'检测失败，请重试',
    sshTitle:'⑦ SSH 安全加固 (端口 / 密钥 / 仅密钥登录)', sshSub:'管理三台服务器的 SSH：修改端口(安全防锁死)、生成登录密钥、设置为仅密钥登录。修改端口前建议先生成密钥。',
    sshRefresh:'刷新状态', sshLoading:'正在查询 SSH 状态', sshSetPort:'修改 SSH 端口', sshGenKey:'生成并下载 SSH 密钥', sshGenHint:'生成 ed25519 密钥, 公钥写入 authorized_keys, 私钥返回下载(服务器不留私钥)', sshDownloadCurrent:'下载当前密钥',
    sshDownload:'下载私钥', sshCopy:'复制私钥', sshEnableKeyOnly:'启用仅密钥登录', sshDisableKeyOnly:'恢复密码登录',
    thTarget:'目标服务器', sshVaultTitle:'SSH 密钥库 (连接新出口用)', sshVaultSub:'上传私钥(权限600)供新出口选择使用；可删除释放磁盘。仅存文件名，私钥不对外展示。', sshUpload:'上传密钥', sshDelete:'删除',
    routeTitle:'⑧ 智能分流规则', routeSub:'按域名/IP/端口智能分流, 命中规则优先于"按入口端口"分流', routeEnable:'启用智能分流',
    routeAdd:'+ 添加规则', routeApply:'保存并应用', routeHint:'示例: 域名后缀 tiktok.com → exit-tag; GeoIP cn → direct',
    portsTitle:'⑨ 端口占用 (每台服务器当前监听的全部端口)', portsSub:'实时查询三台服务器所有监听端口(TCP/UDP)，含地址、协议与进程。SSH / 面板 / Xray 端口会标注。', portsRefresh:'刷新端口', portsNoData:'无监听端口', thProto:'协议', thAddr:'地址', thProc:'进程',
    bruteTitle:'暴力破解防护', bruteSub:'面板登录与 SSH 登录的暴力破解防护。规则: 60 秒内失败 17 次即封锁 17200 秒 (约 4.8 小时)。',
    brutePanel:'面板登录防护 (应用层)', bruteSsh:'SSH 登录防护 (fail2ban)', bruteTarget:'目标服务器',
    bruteRefreshBans:'刷新封锁列表', bruteUnban:'解封', bruteNoBan:'当前无被封锁的 IP',
    bruteRule:'下列参数可随时修改, 保存后立即生效并同步到已启用的 SSH 防护',
    bruteCfgTitle:'防护参数配置 (可修改)', bruteWindow:'统计窗口(秒)', bruteMaxfail:'窗口内最大失败次数', bruteBan:'封锁时长(秒)',
    bruteCfgSave:'保存参数',
    bruteEnabled:'已启用', bruteDisabled:'未启用', bruteNotInst:'未安装',
    bruteSshOn:'fail2ban 运行中, sshd jail 已激活', bruteSshOff:'fail2ban 未运行或 jail 未激活',
    bruteEnable:'启用 SSH 防护', bruteDisable:'停用 SSH 防护',
    bruteEnableConfirm:'确认在所选服务器上启用 fail2ban SSH 防暴? (会安装并配置 60秒/17次/17200秒 规则, 端口按实际 SSH 端口)',
    brutePanelBans:'面板登录被封锁的 IP', bruteSshBans:'SSH 被封锁的 IP',
    machineTitle:'⑪ 应用与配置备份', machineSub:'对指定服务器仅备份其应用与配置 (不含 Debian 系统文件): 面板设置(state.json)/防火墙/xray分流与证书/SSH加固/fail2ban/BBR/sysctl/nginx网站/系统服务。体积很小。备份存储在目标服务器 /opt/x-cfui/machine_backups, 可下载到本地或删除。',
    machineTarget:'目标服务器', machineStart:'开始整机备份', machineRefresh:'刷新列表', machineStatus:'当前状态',
    machineStateIdle:'空闲', machineStateRunning:'备份进行中…', machineStateDone:'上次备份完成', machineStateError:'上次备份失败',
    machineNoBackup:'该服务器暂无整机备份', machineWarn:'注意: 备份存放在目标服务器本机磁盘, 若磁盘故障将一同丢失; 重要数据请下载到本地或其它机器保管。大磁盘整机备份可能需数分钟。',
    machineFilename:'文件名', machineSize:'大小', machineTime:'时间', machineDownload:'下载', machineDelete:'删除',
    machineRunningNote:'备份任务进行中, 请勿重复点击。', machineRcNote:'部分文件在备份期间发生变化 (tar 退出码 1), 属正常现象。', machineStarted:'已启动', machineListEmpty:'（列表为空）',
  },
  en: {
    appName:'x-cfui Panel', bbrTitle:'BBR Status', bbrSub:'BBR is a TCP congestion control algorithm. "Verify Entry BBR" checks the local entry server; each exit node table has its own "Verify BBR" button.',
    bbrBtn:'Verify Entry BBR', exitTitle:'① Exit Nodes', thName:'Name', thAddr:'Address', thPort:'Port', thRelay:'Relay', thOp:'Op',
    btnAddExit:'+ Add Exit', exitHint:'Hint: added exits default to TLS relay + BBR. SSH password is recorded at ③ deploy.',
    inTitle:'② Entry Ports (client port → route to exit)', thExit:'Route to', thSec:'Encryption', thLink:'Client Link (click to copy)', thPortName:'Port/Name',
    btnAddIn:'+ Add Entry', uuidTag:'Global Client UUID (shared by all entries)', btnSaveUuid:'Save UUID',
    provTitle:'③ One-click Deploy New Exit (auto Xray + TLS + BBR)', provSub:'Fill info and click; panel auto: add exit (default 10443/TLS/BBR) → SSH install Xray → record SSH creds.',
    btnProv:'Add & Deploy', fwTitle:'Firewall (on/off / allow / deny ports)', fwSub:'Manage firewall of entry and each exit. Before enabling, SSH(22)/panel(5000)/proxy ports are auto-allowed to avoid lockout. Based on ufw.',
    fwEnable:'Enable Firewall', fwDisable:'Disable Firewall', fwRefresh:'Refresh', fwAllow:'Allow', fwDeny:'Deny', fwApply:'Apply Rule', fwRule:'Firewall rule',
    fwHardenBtn:'Harden Firewall', fwHardenSub:'Allow all listening ports shown above on all three servers; deny all other unused ports (default deny). SSH/panel/proxy ports are in the allow list, no lockout.', fwHardenConfirm:'Allow all listening ports on all three servers and deny the rest?', fwHardenOk:'Firewall hardened on all three servers',
    asTitle:'Boot Auto-start Check', asSub:'Verify per-server Xray / BBR / firewall boot auto-start. This architecture uses no DNAT port forwarding; routing is done inside Xray.', asVerifyAll:'Verify All',
    linkTitle:'④ Client Links (encryption / spoofing / subscription)', linkSub:'Client connection string per entry port. Reality mode has built-in TLS-grade encryption and real-site spoofing.',
    fpLabel:'Client Spoofing Fingerprint', fpSave:'Save Spoof', fpHint:'Note: TLS fingerprint spoofed when client connects to entry server. Shared by all entry ports (443/8443, etc.). Exit servers only relay traffic and are not affected.',
    phHost:'Public Host/Domain', hostSave:'Save Host', hostAdd:'Add Host', hostHint:'Client links and QR codes will connect to the entry server using this address. Ensure the domain resolves to the entry server. Multiple addresses supported — links table generates a connection string per address.', hostEmpty:'Host cannot be empty', collapseOpen:'Expand', collapseClose:'Collapse', navNodes:'Nodes', navRouting:'Routing', navSite:'Site', navClient:'Client', navSecurity:'Security', navOps:'Ops', navAccount:'Account', applyTitle:'⑤ Apply / Status', btnApply:'Apply & Restart Xray', btnRefresh:'Refresh',
    siteSetTitle:'Site Settings (Title / Footer)', siteSetSub:'Customize the browser tab title and footer text. Takes effect immediately after saving.', siteTitleLabel:'Site Title', siteFooterLabel:'Footer Text', siteSetSave:'Save Site Settings', siteSavedOk:'Site settings saved', siteSetEmpty:'Title and footer cannot both be empty',
    backupTitle:'⑩ Backup & Restore', backupSub:'One-click backup of all current settings (nodes / entry ports / routing / public hosts / site settings / security). Download locally or restore from a backup file. A system factory default backup is also maintained.', backupExport:'① Backup & Download', backupDefaultSave:'④ Save as Factory Default Backup', backupUpload:'② Upload Backup', backupRestore:'③ Restore Settings', backupDefaultRestore:'⑤ Import Factory Default Settings', backupHint:'Note: ①~③ are full machine backups (include server IP/port/password/key, for THIS server only). ④⑤ factory default is a portable template that STRIPS all server IP/port/password/key/credentials, keeping only routing rules / smart routing / site title / footer, safe to use on other or future servers. Back up first to avoid data loss.', backupNoFile:'Please select a backup file', backupTime:'Backup time ', backupReady:'Ready to restore', backupRestored:'Restored', backupConfirmRestore:'Restore all settings from uploaded backup? Current settings will be overwritten (backup first recommended).',     backupConfirmDefault:'Save current PORTABLE settings (routing rules / smart routing / site title / footer) as the factory default template? NOTE: no server IP/port/password/key is included, safe for other servers. Overwrites the previous factory default.', backupConfirmImport:'Import the factory default template? Only routing rules / smart routing / site title / footer are applied; this server IP/port/password/key/credentials stay unchanged.', backupSavedTitle:'Saved Server Backups', backupSavedSub:'Each "Backup & Download" automatically keeps a server copy here. You can download, restore, or delete to free space.', backupSavedRefresh:'Refresh List', backupEmpty:'No saved backups yet. Click "Backup & Download" above to create one.', backupFilename:'Filename', backupConfirmDelete:'Delete this backup? This cannot be undone.',
    secTitle:'⑥ Account & Security', secSub:'Change admin account / password and the entry token (re-login after change).', btnSaveSec:'Save Security',
    phExitName:'Exit name (e.g. Russia)', secReality:'Reality (recommended)', secTls:'TLS', secNone:'None',
    copied:'Link copied', copyFail:'Copy failed, select manually', notActive:'None', reality:'Reality', tls:'TLS',
    bbrOn:'On', bbrOff:'Off', relayTls:'TLS', relayPlain:'Plain',
    yes:'Yes', no:'No', fwOn:'Enabled', fwOff:'Disabled', fwNotInst:'Not installed',
    del:'Delete', openBbr:'Enable BBR', verifyBbr:'Verify BBR',
    rename:'Rename', clickRename:'Click name to edit', save:'Save', cancel:'Cancel',
    asXray:'Xray Service', asBbr:'BBR', asFw:'Firewall', asPf:'Port Forward', asAdmin:'Panel Service',
    asAllOk:'All boot auto-start OK', asSomeIssue:'Some items not auto-start', verifyOk:'Check done', needSsh:'Missing SSH password, enter in prompt',
    fwInfo:'Not queried', fwLoading:'Querying firewall status', themeNight:'Theme: Night', themeDay:'Theme: Day', bootAuto:'Boot auto',
    bbrOk:'BBR acceleration active (auto-start on boot)', bbrOff:'BBR not active, current algo', bbrNoAuto:'BBR active but not auto-start on boot (lost after reboot)', bbrCheckFail:'Check failed, retry',
    sshTitle:'⑦ SSH Hardening (port / key / key-only)', sshSub:'Manage SSH of the three servers: change port (safe, anti-lockout), generate login key, enforce key-only login.',
    sshRefresh:'Refresh', sshLoading:'Querying SSH status', sshSetPort:'Change SSH Port', sshGenKey:'Gen & Download Key', sshGenHint:'Generate ed25519 key, append pubkey to authorized_keys, return private key for download (no key left on server)', sshDownloadCurrent:'Download Current Key',
    sshDownload:'Download Key', sshCopy:'Copy Key', sshEnableKeyOnly:'Enable Key-Only', sshDisableKeyOnly:'Restore Password',
    thTarget:'Target', sshVaultTitle:'SSH Key Vault (for new exits)', sshVaultSub:'Upload private key (chmod 600) for new exits; delete to free disk. Only the filename is stored, key is not exposed.', sshUpload:'Upload Key', sshDelete:'Delete',
    routeTitle:'⑧ Smart Routing Rules', routeSub:'Route by domain/IP/port; matched rules take priority over per-port routing', routeEnable:'Enable smart routing',
    routeAdd:'+ Add Rule', routeApply:'Save & Apply', routeHint:'e.g. domain_suffix tiktok.com → exit-tag; GeoIP cn → direct',
    portsTitle:'⑨ Port Usage (all listening ports per server)', portsSub:'Live query of all listening TCP/UDP ports on each of the three servers, with addr/proto/process. SSH/panel/Xray ports are tagged.', portsRefresh:'Refresh Ports', portsNoData:'No listening ports', thProto:'Proto', thAddr:'Address', thProc:'Process',
    bruteTitle:'Brute-force Protection', bruteSub:'Protection for panel login and SSH login brute-force. Rule: 17 failed attempts within 60s triggers a 17200s (≈4.8h) ban.',
    brutePanel:'Panel Login Protection (app-layer)', bruteSsh:'SSH Protection (fail2ban)', bruteTarget:'Target',
    bruteRefreshBans:'Refresh Ban List', bruteUnban:'Unban', bruteNoBan:'No banned IPs currently',
    bruteRule:'These parameters can be modified anytime; changes apply immediately and sync to enabled SSH protection',
    bruteCfgTitle:'Protection Parameters (editable)', bruteWindow:'Window (sec)', bruteMaxfail:'Max fails in window', bruteBan:'Ban duration (sec)',
    bruteCfgSave:'Save Parameters',
    bruteEnabled:'Enabled', bruteDisabled:'Disabled', bruteNotInst:'Not Installed',
    bruteSshOn:'fail2ban running, sshd jail active', bruteSshOff:'fail2ban not running or jail inactive',
    bruteEnable:'Enable SSH Protection', bruteDisable:'Disable SSH Protection',
    bruteEnableConfirm:'Enable fail2ban SSH protection on the selected server? (installs & configures 60s/17/17200s rule, port = actual SSH port)',
    brutePanelBans:'Panel-login banned IPs', bruteSshBans:'SSH banned IPs',
    machineTitle:'⑪ App & Config Backup', machineSub:'Backup only the applications and configuration on the selected server (no Debian system files): panel settings (state.json) / firewall / xray routing & certs / SSH hardening / fail2ban / BBR / sysctl / nginx sites / system services. Small size. Stored on the target at /opt/x-cfui/machine_backups. Download or delete from here.',
    machineTarget:'Target', machineStart:'Start Full Backup', machineRefresh:'Refresh List', machineStatus:'Current Status',
    machineStateIdle:'Idle', machineStateRunning:'Backup in progress…', machineStateDone:'Last backup done', machineStateError:'Last backup failed',
    machineNoBackup:'No full-machine backup on this server yet', machineWarn:'Note: backups live on the target server local disk; if the disk fails the backup is lost too. Download important backups to local/other machines. Large disks may take several minutes.',
    machineFilename:'File', machineSize:'Size', machineTime:'Time', machineDownload:'Download', machineDelete:'Delete',
    machineRunningNote:'A backup is already running; please do not click again.', machineRcNote:'Some files changed during backup (tar exit code 1) — normal.', machineStarted:'Started', machineListEmpty:'(empty)',
  }
};
function t(k){ return (I18N[LANG] && I18N[LANG][k]) || (I18N.zh[k]) || k; }

function applyLang(){
  document.documentElement.lang = (LANG==='zh') ? 'zh-CN' : 'en';
  document.documentElement.setAttribute('data-theme', THEME);
  document.getElementById('langBtn').textContent = (LANG==='zh') ? 'EN' : '中文';
  document.getElementById('themeBtn').textContent = (THEME==='dark') ? t('themeNight') : t('themeDay');
  document.querySelectorAll('[data-i18n]').forEach(el=>{ el.textContent = t(el.getAttribute('data-i18n')); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>{ el.placeholder = t(el.getAttribute('data-i18n-ph')); });
  document.title = 'x-cfui';
  wireCollapse();
}
function wireCollapse(){
  const EXP_KEY = 'xc_expanded';
  const saved = JSON.parse(localStorage.getItem(EXP_KEY) || '[]');
  const set = new Set(saved);
  document.querySelectorAll('.card').forEach((card,i)=>{
    const h2 = card.querySelector(':scope > h2');
    if(!h2) return;
    const old = h2.querySelector(':scope > .ctoggle'); if(old) old.remove();
    const oldT = h2.querySelector(':scope > .ctext'); if(oldT) oldT.remove();
    const tog = document.createElement('span'); tog.className='ctoggle';
    const ctext = document.createElement('span'); ctext.className='ctext';
    const setIcon = ()=>{
      const collapsed = card.classList.contains('collapsed');
      tog.textContent = collapsed ? '▸' : '▾';   // 折叠=指向右的箭头, 展开=指向下
      ctext.textContent = collapsed ? t('collapseOpen') : t('collapseClose');
    };
    h2.appendChild(tog); h2.appendChild(ctext);
    const key = h2.getAttribute('data-i18n') || ('card'+i);
    // 默认全部折叠; 仅当用户之前手动展开过该卡片(key 在展开集合)才展开
    if(set.has(key)) card.classList.remove('collapsed'); else card.classList.add('collapsed');
    setIcon();
    h2.onclick = ()=>{
      const collapsed = card.classList.toggle('collapsed');
      const s = new Set(JSON.parse(localStorage.getItem(EXP_KEY) || '[]'));
      if(collapsed) s.delete(key); else s.add(key);
      localStorage.setItem(EXP_KEY, JSON.stringify([...s]));
      setIcon();
    };
  });
}
function switchNav(nav){
  document.querySelectorAll('.section').forEach(s=> s.classList.toggle('active', s.getAttribute('data-nav')===nav));
  document.querySelectorAll('.navbtn').forEach(b=> b.classList.toggle('active', b.getAttribute('data-nav')===nav));
  localStorage.setItem('xc_nav', nav);
  if(nav==='ops' && typeof machineLoad==='function'){ machineLoad(); }
}
function initNav(){
  const nav = localStorage.getItem('xc_nav') || 'nodes';
  switchNav(nav);
}
function toggleTheme(){
  THEME = (THEME==='dark') ? 'light' : 'dark';
  localStorage.setItem('xc_theme', THEME);
  applyLang();
}
function toggleLang(){
  LANG = (LANG==='zh') ? 'en' : 'zh';
  localStorage.setItem('xc_lang', LANG);
  applyLang();
  loadState();
}

const api = async (path, method='GET', body=null) => {
  const opt = {method, headers:{'Content-Type':'application/json'}};
  if(body) opt.body = JSON.stringify(body);
  try {
    const r = await fetch(BASE + path, opt);
    const tt = await r.text();
    try { return JSON.parse(tt); }
    catch(e){ return {ok:false, msg:"server error: "+(tt.slice(0,200)||r.status)}; }
    } catch(e){ return {ok:false, msg:"network error: "+e.message}; }
};
// 调用需要 SSH 密码的接口: 优先用面板已保存(服务端)的凭据, 仅当服务端确实缺少密码时才弹窗询问, 避免每次手动输入
async function apiWithSsh(path, body){
  let r=await api(path,'POST',body);
  if(!r.ok && /ssh|密码|password/i.test((r.msg||'')+(r.log||''))){
    const pw=prompt(t('needSsh')); if(pw===null) return r;
    body.ssh_pass=pw; r=await api(path,'POST',body);
  }
  return r;
}
let _toastTimer=null;
function show(msg, ok){
  const el=document.getElementById('toast');
  if(_toastTimer)clearTimeout(_toastTimer);
  el.style.display='block';el.style.opacity='1';
  el.style.background=ok?'var(--ok)':'var(--err)';
  el.style.color=ok?'#fff':'#fff';
  el.textContent=msg;
  _toastTimer=setTimeout(()=>{ el.style.opacity='0'; setTimeout(()=>el.style.display='none',300); },3000);
}
function genUUID(){
  if(window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c=>{
    const r=Math.random()*16|0, v=c==='x'?r:(r&0x3|0x8);
    return v.toString(16);
  });
}
function fillExits(){
  const ex=document.getElementById('in_exit');
  ex.innerHTML='';
  STATE.exits.forEach(e=>{ ex.add(new Option(`${e.name} (${e.address}:${e.port})`, e.tag)); });
  const fw=document.getElementById('fw_target');
  fw.innerHTML='';
  fw.add(new Option('入口 (本机)', 'entry'));
  STATE.exits.forEach((e,i)=>{ fw.add(new Option(`${e.name} (${e.address})`, 'exit:'+i)); });
}
function secBadge(sec){ return sec==='reality'?'<span class="badge enc">'+t('reality')+'</span>':sec==='tls'?'<span class="badge enc">'+t('tls')+'</span>':'<span class="badge warn">'+t('notActive')+'</span>'; }
function ynb(b){ return b?'<span class="badge yes">'+t('yes')+'</span>':'<span class="badge no">'+t('no')+'</span>'; }
let STATE;
async function loadState(){
  STATE = await api('/api/state');
  document.getElementById('client_uuid').value = STATE.client_uuid;
  document.getElementById('client_fp').value = STATE.client_fp || 'chrome';
  renderHosts();
  document.getElementById('site_title_input').value = STATE.site_title || 'x-cfui';
  document.getElementById('site_footer_input').value = STATE.site_footer || 'QQ: 123008';
  applySiteSettings(STATE.site_title, STATE.site_footer);
  const et=document.querySelector('#exitTable tbody'); et.innerHTML='';
  STATE.exits.forEach((e,i)=>{
    const relay=e.relay_security||'tls';
    const relayBadge = relay==='tls'?'<span class="badge enc">'+t('relayTls')+'</span>':'<span class="badge warn">'+t('relayPlain')+'</span>';
    const bbrBadge = e.bbr?'<span class="badge ok">'+t('bbrOn')+'</span>':'<span class="badge warn">'+t('bbrOff')+'</span>';
    et.insertAdjacentHTML('beforeend', `<tr>
      <td id="nm_exit_${i}"><span class="node-name" title="${t('clickRename')}" onclick="startEditName('exit',${i})">${e.name}</span></td><td>${e.address}</td><td>${e.port}</td><td><span class="tag">${e.uuid.slice(0,8)}…</span></td>
      <td>${relayBadge}</td><td>${bbrBadge}</td>
      <td><a class="link" onclick="startEditName('exit',${i})">${t('rename')}</a><a class="link" onclick="delExit(${i})">${t('del')}</a><a class="link" onclick="toggleBbr(${i})">${t('openBbr')}</a><a class="link" onclick="checkBbrExit(${i})">${t('verifyBbr')}</a><br><span id="bbrExit_${i}" class="tag" style="display:none"></span></td></tr>`);
  });
  const it=document.querySelector('#inTable tbody'); it.innerHTML='';
  STATE.inbounds.forEach((b,i)=>{
    const exName=(STATE.exits.find(x=>x.tag===b.exit)||{}).name||b.exit;
    it.insertAdjacentHTML('beforeend', `<tr>
      <td><b>${b.port}</b></td><td id="nm_inbound_${i}"><span class="node-name" title="${t('clickRename')}" onclick="startEditName('inbound',${i})">${b.name}</span></td><td><span class="tag">${exName}</span></td>
      <td>${secBadge(b.security)}</td><td><span class="tag">${STATE.client_uuid.slice(0,8)}…</span></td>
      <td><a class="link" onclick="startEditName('inbound',${i})">${t('rename')}</a><a class="link" onclick="delInbound(${i})">${t('del')}</a></td></tr>`);
  });
  const lt=document.querySelector('#linkTable tbody'); lt.innerHTML='';
  const hosts=STATE.public_hosts||[];
  STATE.inbounds.forEach((b)=>{
    const rows = hosts.length > 0 ? hosts : [location.hostname];
    rows.forEach((host, hi)=>{
      const link=clientLink(b, host);
      const hostLabel = hosts.length > 1 ? `<span class="tag" style="font-size:11px">${escHtml(host)}</span> ` : '';
      lt.insertAdjacentHTML('beforeend', `<tr><td><b>${b.port}</b> ${b.name}</td><td>${secBadge(b.security)}</td>
        <td>${hostLabel}<span class="code" id="lk_${b.port}_${hi}">${link}</span> <button class="copybtn" onclick="copyLink('${b.port}_${hi}')">复制</button>
        ${b.security==='reality'&&b.reality?`<br><span class="tag">伪装域名: ${b.reality.serverName} · 公钥: ${b.reality.publicKey.slice(0,16)}… · SID: ${b.reality.shortId}</span>`:''}
        <br><img src="${BASE}/api/qr?text=${encodeURIComponent(link)}" alt="QR" style="margin-top:6px;width:150px;height:150px;background:#fff;border-radius:6px">
        </td></tr>`);
    });
  });
  fillExits();
  document.getElementById('sec_user').value = STATE.admin_user || 'admin';
  document.getElementById('sec_token').value = STATE.entry_token || 'aa888888';
  document.getElementById('sec_hint').textContent = `${t('secTitle')}: /${STATE.entry_token||'aa888888'} · ${STATE.admin_user||'admin'}`;
  fwStatus();
  portsLoad();
}
function copyLink(port){
  const tt=document.getElementById('lk_'+port).textContent;
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(tt).then(()=>show(t('copied'),true)).catch(()=>fallbackCopy(tt));
  } else { fallbackCopy(tt); }
}
function fallbackCopy(tt){
  const ta=document.createElement('textarea'); ta.value=tt; ta.style.position='fixed'; ta.style.opacity='0'; ta.style.top='0'; ta.style.left='0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try{ document.execCommand('copy'); show(t('copied'),true); }catch(e){ show(t('copyFail'),false); }
  document.body.removeChild(ta);
}
async function addExit(){
  const name=document.getElementById('ex_name').value.trim();
  const addr=document.getElementById('ex_addr').value.trim();
  const uuid=document.getElementById('ex_uuid').value.trim() || genUUID();
  if(!name||!addr){ show(t('exitHint'),false); return; }
  const r=await api('/api/exit','POST',{name,address:addr,uuid});
  show(r.msg,r.ok); if(r.ok) loadState();
}
function bbrLine(r){
  const name = r.name || '入口';
  const host = r.host || window.location.hostname;
  if(!r || !r.cca){
    return `<span class="warnline">⚠️ <b>${name} (${host})</b> — ${t('bbrCheckFail')||'检测失败，请重试'}</span>`;
  }
  if(r.cca === 'bbr' && r.boot_auto){
    return `<span class="okline">✅ <b>${name} (${host})</b> — ${t('bbrOk')}</span>`;
  }
  if(r.cca !== 'bbr'){
    return `<span class="warnline">⚠️ <b>${name} (${host})</b> — ${t('bbrOff')}: ${r.cca}</span>`;
  }
  return `<span class="warnline">⚠️ <b>${name} (${host})</b> — ${t('bbrNoAuto')}</span>`;
}
async function checkBbr(){
  const r=await api('/api/bbr_status');
  if(!r.ok){ show(t('verifyBbr')+': '+r.msg,false); return; }
  const el=document.getElementById('bbrStatus');
  el.innerHTML = bbrLine({name:'入口服务器', host:window.location.hostname, cca:r.cca, boot_auto:r.boot_auto});
  show('入口 BBR: '+r.cca, r.ok);
}
async function checkBbrExit(i){
  const el=document.getElementById('bbrExit_'+i);
  el.style.display='block'; el.textContent=t('verifyBbr')+'...';
  const r=await api('/api/bbr_status?index='+i);
  if(!r.ok){ el.textContent='✕ '+r.msg; return; }
  const ex = STATE.exits[i] || {};
  el.innerHTML = bbrLine({name: ex.name, host: ex.address, cca:r.cca, boot_auto:r.boot_auto});
}
async function delExit(i){ const r=await api('/api/exit','DELETE',{index:i}); show(r.msg,r.ok); if(r.ok) loadState(); }
async function addInbound(){
  const port=document.getElementById('in_port').value.trim();
  const name=document.getElementById('in_name').value.trim();
  const exit=document.getElementById('in_exit').value;
  const sec=document.getElementById('in_sec').value;
  const sni=document.getElementById('in_sni').value.trim();
  if(!port){ show(t('thPort')+'?',false); return; }
  const r=await api('/api/inbound','POST',{port:parseInt(port),name:name||('端口'+port),exit,security:sec,sni});
  show(r.msg,r.ok); if(r.ok) loadState();
}
async function delInbound(i){ const r=await api('/api/inbound','DELETE',{index:i}); show(r.msg,r.ok); if(r.ok) loadState(); }
// ---- 节点显示名称内联编辑 (出口节点 / 入口线路) ----
function escAttr(s){ return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function startEditName(kind, i){
  const obj = kind==='exit' ? STATE.exits[i] : STATE.inbounds[i];
  if(!obj) return;
  const cur = obj.name || '';
  const td = document.getElementById('nm_'+kind+'_'+i);
  if(!td) return;
  if(document.getElementById('nm_inp_'+kind+'_'+i)) return; // 已在编辑中
  td.innerHTML = `<input id="nm_inp_${kind}_${i}" value="${escAttr(cur)}" style="min-width:110px" onkeydown="if(event.key==='Enter'){commitEditName('${kind}',${i});}else if(event.key==='Escape'){cancelEditName('${kind}',${i});}"> <a class="link" onclick="commitEditName('${kind}',${i})">${t('save')}</a><a class="link" onclick="cancelEditName('${kind}',${i})">${t('cancel')}</a>`;
  const el = document.getElementById('nm_inp_'+kind+'_'+i);
  el.focus(); el.select();
}
async function commitEditName(kind, i){
  const inp = document.getElementById('nm_inp_'+kind+'_'+i);
  if(!inp) return;
  const name = inp.value.trim();
  if(!name){ show(t('clickRename')+' / 名称不能为空', false); return; }
  try{
    const r = await api('/api/'+kind+'_rename','POST',{index:i, name});
    show(r.msg, r.ok);
    if(r.ok) loadState(); // 成功后整体重渲染, 新名称同步到所有表格与链接
  }catch(e){ show('操作异常: '+e, false); }
}
function cancelEditName(kind, i){ loadState(); }
async function saveClientUuid(){
  const v=document.getElementById('client_uuid').value.trim();
  if(!v){ show(t('uuidTag'),false); return; }
  const r=await api('/api/client_uuid','POST',{uuid:v}); show(r.msg,r.ok);
}
async function saveFp(){
  const fp=document.getElementById('client_fp').value;
  const r=await api('/api/client_fp','POST',{fp});
  show(r.msg||'fp saved', r.ok); if(r.ok) loadState();
}
async function addHost(){
  const h=document.getElementById('public_host_input').value.trim();
  if(!h){ show(t('hostEmpty'), false); return; }
  const r=await api('/api/public_host','POST',{action:'add', host:h});
  show(r.msg||'host added', r.ok); if(r.ok){ document.getElementById('public_host_input').value=''; loadState(); }
}
async function delHost(i){
  if(!confirm('确定删除该地址?')) return;
  const r=await api('/api/public_host','POST',{action:'delete', index:i});
  show(r.msg||'host deleted', r.ok); if(r.ok) loadState();
}
function renderHosts(){
  const box=document.getElementById('hosts_list');
  if(!box) return;
  box.innerHTML='';
  const hosts=STATE.public_hosts||[];
  hosts.forEach((h,i)=>{
    const row=document.createElement('div');
    row.style.cssText='display:flex;gap:6px;margin:3px 0;align-items:center';
    row.innerHTML=`<span class="tag" style="flex:1;text-align:left;word-break:break-all;font-size:13px">${escHtml(h)}</span><button class="sec" onclick="delHost(${i})" title="${t('del')}">✕</button>`;
    box.appendChild(row);
  });
}
function escHtml(s){ const d=document.createElement('span'); d.textContent=s; return d.innerHTML; }
async function saveSiteSettings(){
  const title=document.getElementById('site_title_input').value.trim();
  const footer=document.getElementById('site_footer_input').value.trim();
  if(!title&&!footer){ show(t('siteSetEmpty'), false); return; }
  const r=await api('/api/site_settings','POST',{site_title:title, site_footer:footer});
  show(r.msg||'saved', r.ok);
  if(r.ok){ applySiteSettings(r.site_title, r.site_footer); }
}
function applySiteSettings(title, footer){
  document.getElementById('page_title').textContent=title||'x-cfui';
  const el=document.getElementById('page_footer');
  if(el) el.textContent=footer||'QQ: 123008';
}
function clientLink(b, host){
  const u=STATE.client_uuid, h=host||(STATE.public_hosts&&STATE.public_hosts[0])||location.hostname, port=b.port, name=encodeURIComponent(b.name);
  const fp=STATE.client_fp||'chrome';
  if(b.security==='reality'){
    const r=b.reality||{};
    return `vless://${u}@${h}:${port}?type=tcp&security=reality&sni=${r.serverName||''}&fp=${fp}&pbk=${r.publicKey||''}&sid=${r.shortId||''}&spx=%2F#${name}`;
  } else if(b.security==='tls'){
    return `vless://${u}@${h}:${port}?type=tcp&security=tls&fp=${fp}#${name}`;
  }
  return `vless://${u}@${h}:${port}?type=tcp&security=none#${name}`;
}
async function applyConfig(){
  const r=await api('/api/apply','POST',{}); show(r.msg,r.ok);
  if(r.ok){ document.getElementById('xray_stat').innerHTML='<span class="badge ok">Xray '+t('asXray')+'</span>'; }
}
async function toggleBbr(i){
  const e=STATE.exits[i];
  const body={index:i, ssh_user:e.ssh_user||'root', ssh_pass:e.ssh_pass||'', ssh_port:e.ssh_port||22};
  show(t('openBbr')+': '+e.name+' ...',true);
  const r=await apiWithSsh('/api/bbr', body);
  show(r.msg,r.ok); if(r.ok){ e.bbr=true; loadState(); }
}
async function saveSecurity(){
  const user=document.getElementById('sec_user').value.trim();
  const pass=document.getElementById('sec_pass').value;
  const pass2=document.getElementById('sec_pass2').value;
  const token=document.getElementById('sec_token').value.trim();
  if(!user){ show(t('secTitle'),false); return; }
  if(pass && pass!==pass2){ show('password mismatch',false); return; }
  if(token && !/^[A-Za-z0-9]+$/.test(token)){ show('token alpha-num',false); return; }
  const r=await api('/api/security','POST',{admin_user:user, admin_pass:pass, entry_token:token});
  show(r.msg,r.ok);
  if(r.ok){
    if(token && token!==(STATE.entry_token||'aa888888')){ setTimeout(()=>{ window.location.href='/'+token; },1200); }
    else loadState();
  }
}
async function provisionExit(){
  const name=document.getElementById('prov_name').value.trim();
  const addr=document.getElementById('prov_addr').value.trim();
  const user=document.getElementById('prov_user').value.trim()||'root';
  const pass=document.getElementById('prov_pass').value;
  const sshport=parseInt(document.getElementById('prov_sshport').value)||22;
  const ssh_key=document.getElementById('prov_ssh_key').value;
  if(!name||!addr){ show(t('exitHint'),false); return; }
  if(!pass && !ssh_key){ show(t('needSsh'),false); return; }
  const log=document.getElementById('prov_log'); log.style.display='block'; log.textContent=t('btnProv')+'...';
  const r=await api('/api/provision','POST',{name,address:addr,ssh_user:user,ssh_pass:pass,ssh_port:sshport,ssh_key});
  log.textContent=r.log||r.msg; show(r.msg,r.ok);
  if(r.ok) loadState();
}
// ---- firewall ----
function fwTarget(){
  const v=document.getElementById('fw_target').value;
  if(v==='entry' || v==='cn') return {target:'entry'};
  const i=parseInt(v.split(':')[1]);
  const e=STATE.exits[i];
  return {target:'exit', index:i, exit:e};
}
async function fwStatus(){
  const info=document.getElementById('fw_info');
  const out=document.getElementById('fw_out');
  info.innerHTML='<span style="color:var(--acc);animation:spin 0.8s linear infinite;display:inline-block;margin-right:4px">⟳</span> '+t('fwLoading')+'...';
  info.style.opacity='0.7';
  out.style.display='none';
  try {
    const tg=fwTarget();
    let url='/api/firewall?target='+tg.target;
    if(tg.target==='exit') url+='&index='+tg.index;
    const r=await api(url);
    info.style.opacity='';
    const who = (tg.target==='entry'||tg.target==='cn') ? '入口' : (tg.exit?.name || '出口');
    if(!r.ok){ info.textContent=t('fwInfo')+': '+r.msg; out.style.display='none'; return; }
    if(!r.installed){
      info.textContent = who+' — '+t('fwNotInst');
      out.style.display='none'; return;
    }
    const s = r.active?t('fwOn'):t('fwOff');
    if(r.rules && r.rules.length){
      const allow=[], deny=[];
      r.rules.forEach(ln=>{
        const port=(ln.match(/(\d+)\/(tcp|udp)/)||[])[0]||ln.trim();
        if(/DENY/i.test(ln)) deny.push(port);
        else if(/ALLOW/i.test(ln)) allow.push(port);
      });
      info.textContent = who+' — '+s;
      out.style.display='block';
      out.textContent = who+' — '+s+'\n'+t('fwAllow')+': '+(allow.length?allow.join(', '):'-')+'\n'+t('fwDeny')+': '+(deny.length?deny.join(', '):'-');
    } else {
      info.textContent = who+' — '+s;
      out.style.display='block';
      out.textContent = who+' — '+s+'\n'+t('fwAllow')+': -\n'+t('fwDeny')+': -';
    }
  } catch(e) { show('防火墙查询异常: '+e.message, false); }
}
async function fwToggle(action){
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳ 处理中...';
  try {
    const tg=fwTarget();
    const body={target:tg.target, action};
    if(tg.target==='exit'){ body.index=tg.index; body.ssh_user=tg.exit.ssh_user||'root'; body.ssh_port=tg.exit.ssh_port||22; body.ssh_pass=tg.exit.ssh_pass||''; }
    const r=await apiWithSsh('/api/firewall', body);
    if(!r.ok){ show(t('fwTitle')+': '+r.msg,false); return; }
    show(t('fwTitle')+': '+(action==='enable'?t('fwEnable'):t('fwDisable'))+' OK', true);
    setTimeout(()=>fwStatus(), 300);
  } catch(e) { show('防火墙操作异常: '+e.message, false); }
  finally { btn.disabled = false; btn.textContent = origText; }
}
async function fwRule(){
  const tg=fwTarget();
  const port=document.getElementById('fw_port').value.trim();
  const proto=document.getElementById('fw_proto').value;
  const rule=document.getElementById('fw_rule').value;
  if(!port){ show('port?',false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳ 应用中...';
  try {
    const body={target:tg.target, action:rule, port, proto};
    if(tg.target==='exit'){ body.index=tg.index; body.ssh_user=tg.exit.ssh_user||'root'; body.ssh_port=tg.exit.ssh_port||22; body.ssh_pass=tg.exit.ssh_pass||''; }
    const r=await apiWithSsh('/api/firewall', body);
    if(!r.ok){ show(t('fwRule')+': '+r.msg,false); return; }
    show(t('fwRule')+' '+port+'/'+proto+' '+rule+' OK', true);
    setTimeout(()=>fwStatus(), 300);
  } catch(e) { show('规则应用异常: '+e.message, false); }
  finally { btn.disabled = false; btn.textContent = origText; }
}
// ---- autostart verify ----
function asRow(name, host, d){
  if(!d || !d.ok){
    return `<div class="card" style="margin-bottom:8px"><b>${name} (${host})</b> — <span class="badge no">${t('no')}</span> ${d?d.msg:''}</div>`;
  }
  const xray = (d.xray_enabled&&d.xray_active)?'<span class="badge yes">'+t('yes')+'</span>':'<span class="badge no">'+t('no')+'</span>';
  const bbr = (d.bbr_persist&&d.bbr_active)?'<span class="badge yes">'+t('yes')+'</span>':'<span class="badge no">'+t('no')+'</span>';
  const fw = d.firewall_enabled?'<span class="badge yes">'+t('yes')+'</span>':'<span class="badge warn">'+t('no')+'</span>';
  return `<div class="card" style="margin-bottom:8px">
    <b>${name} (${host})</b><br>
    ${t('asXray')}: ${xray} &nbsp; ${t('asBbr')}: ${bbr} &nbsp; ${t('asFw')}: ${fw}<br>
    <span class="tag">${t('asPf')}: ${d.port_forward||'-'}</span>
  </div>`;
}
async function verifyAll(){
  const box=document.getElementById('as_list');
  box.innerHTML='<span class="tag">'+t('asVerifyAll')+'...</span>';
  const r=await api('/api/autostart_all');
  if(!Array.isArray(r)){ box.innerHTML='<span class="badge no">'+t('no')+'</span>'; return; }
  let html='';
  r.forEach(s=>{ html += asRow(s.name||s.host, s.host, s); });
  box.innerHTML=html;
  show(t('verifyOk'), true);
}
// ---- ports usage ----
async function portsLoad(){
  const box=document.getElementById('ports_box');
  box.innerHTML='<span class="tag">'+t('portsRefresh')+'...</span>';
  const r=await api('/api/ports');
  if(!r.ok){ box.innerHTML='<span class="badge no">'+t('no')+'</span>'; return; }
  const servers=r.servers||{};
  // 已知端口标注: SSH / 面板 / 各 Xray 入口与出口
  const known={};
  const addKnown=(p,label)=>{ if(p) known[parseInt(p)]=label; };
  addKnown(5000,'面板');
  addKnown(22,'SSH');
  (STATE&&STATE.inbounds||[]).forEach(b=>addKnown(b.port,'Xray入口'));
  (STATE&&STATE.exits||[]).forEach(e=>addKnown(e.port,'Xray出口'));
  let html='';
  for(const k of Object.keys(servers)){
    const s=servers[k];
    if(!s) continue;
    html += `<h3 style="margin:12px 0 6px;color:var(--acc)">${s.name||k} <span class="tag">${s.host||''}</span></h3>`;
    if(!s.ok){ html += `<span class="badge no">查询失败: ${s.msg||''}</span>`; continue; }
    const ports=s.ports||[];
    if(!ports.length){ html += `<span class="tag">${t('portsNoData')}</span>`; continue; }
    html += `<table><thead><tr><th>${t('thProto')}</th><th>${t('thAddr')}</th><th>${t('thPort')}</th><th>${t('thProc')}</th><th>标记</th></tr></thead><tbody>`;
    ports.forEach(p=>{
      const label=known[p.port]||'';
      const tag=label?`<span class="badge enc">${label}</span>`:'';
      html += `<tr><td>${p.proto}</td><td>${p.addr}</td><td><b>${p.port}</b></td><td>${p.proc||''}</td><td>${tag}</td></tr>`;
    });
    html += `</tbody></table>`;
  }
  box.innerHTML=html;
  document.getElementById('ports_time').textContent = new Date().toLocaleTimeString();
}
// ---- ⑨ 一键加固防火墙 ----
async function fwHarden(){
  if(!confirm(t('fwHardenConfirm'))) return;
  const btn=document.activeElement;
  if(btn){ btn.disabled=true; const ot=btn.textContent; btn.textContent='⏳ 加固中...'; }
  try {
    const msg=document.getElementById('fw_harden_msg');
    const out=document.getElementById('fw_harden_out');
    msg.textContent=t('fwHardenBtn')+'...'; out.style.display='none';
    const r=await api('/api/firewall_harden','POST',{});
    if(!r.ok){ msg.textContent='✕ '+t('no'); show(t('fwTitle')+': '+(r.msg||''),false); return; }
    const res=r.results||{};
    let txt='';
    for(const k of Object.keys(res)){
      const s=res[k]||{};
      if(!s.ok){ txt+=`【${k}】✕ ${s.msg||'失败'}\n`; continue; }
      const allowed=(s.allowed||[]).join(', ');
      const act=s.active?'启用':'未启用';
      txt+=`【${k}】✓ 防火墙${act}, 已放行 ${s.allowed? s.allowed.length:0} 个端口: ${allowed}\n`;
  }
  out.textContent=txt; out.style.display='block';
  msg.textContent='✓ '+t('fwHardenOk');
  show(t('fwHardenOk'), true);
  } catch(e) { show('一键加固异常: '+e.message, false); }
  if(btn){ btn.disabled=false; btn.textContent=ot||t('fwHardenBtn'); btn.blur(); }
}
// ---- SSH 安全加固 ----
function sshTarget(){ return document.getElementById('ssh_target').value; }
async function sshStatus(){
  const tgt = sshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const info = document.getElementById('ssh_info');
  const out = document.getElementById('ssh_out');
  info.innerHTML='<span style="color:var(--acc);animation:spin 0.8s linear infinite;display:inline-block;margin-right:4px">⟳</span> '+t('sshLoading')+'...';
  out.style.display='none'; info.style.opacity='0.7';
  try {
    const r = await api('/api/ssh_status?target='+tgt);
    info.style.opacity='';
    if(!r.ok){ info.textContent = '查询失败: ' + (r.msg||''); out.style.display='none'; return; }
    let html = `${tgt.toUpperCase()} — 端口 <b>${r.port}</b> | 密码登录: <b>${r.password_auth}</b> | 密钥登录: ${r.pubkey_auth} | Root登录: ${r.permit_root} | authorized_keys: ${r.authorized_keys} 个 | 防火墙: ${r.firewall}<br>累计暴力破解失败: <b style="color:#e74c3c">${r.fail_total}</b> 次, 近24h: <b style="color:#e74c3c">${r.fail_24h}</b> 次`;
    if(r.fail_24h > 0 || r.fail_total > 0){
      html += '<br><span class="warnline">⚠️ 该服务器正在遭受 SSH 暴力破解, 强烈建议: 修改端口 + 仅密钥登录</span>';
    }
    info.innerHTML = html;
    out.style.display='block';
    out.textContent = JSON.stringify(r, null, 2);
  } catch(e) {
    show('查询异常: '+e.message, false);
  }
}
async function sshSetPort(){
  const tgt = sshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const v = document.getElementById('ssh_port').value.trim();
  if(!v){ show('请输入新SSH端口', false); return; }
  const port = parseInt(v);
  if(!(port>0 && port<=65535)){ show('端口范围 1-65535', false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳ 修改中...';
  try {
    show('修改端口中(双端口过渡+回滚保护)...', true);
    const r = await api('/api/ssh_set_port','POST',{target:tgt, port});
    show(r.msg, r.ok);
    if(r.ok) setTimeout(()=>sshStatus(), 500);
  } catch(e) {
    show('操作异常: '+e.message, false);
  } finally {
    btn.disabled = false; btn.textContent = origText;
  }
}
async function sshGenKey(){
  const tgt = sshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳ 生成中...';
  try {
    show('生成密钥中...', true);
    const r = await api('/api/ssh_gen_key','POST',{target:tgt});
    const out = document.getElementById('ssh_out');
    const box = document.getElementById('ssh_keybox');
    out.style.display='block';
    out.textContent = r.msg + (r.pub ? ('\n公钥: '+r.pub) : '');
    if(r.ok && r.priv){
      document.getElementById('ssh_priv').value = r.priv;
      box.style.display='block';
    }
    show(r.msg, r.ok);
  } catch(e) {
    show('操作异常: '+e.message, false);
  } finally {
    btn.disabled = false; btn.textContent = origText;
  }
}
function sshDownloadKey(){
  const v = document.getElementById('ssh_priv').value;
  if(!v){ show('没有可下载的私钥', false); return; }
  const blob = new Blob([v], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'id_ed25519_' + sshTarget() + '.pem';
  a.click();
}
async function sshDownloadCurrent(){
  const tgt = sshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳ 获取中...';
  try {
    show('获取当前密钥中...', true);
    const r = await api('/api/ssh_download_key?target='+tgt);
    const box = document.getElementById('ssh_keybox');
    if(r.ok && r.priv){
      document.getElementById('ssh_priv').value = r.priv;
      box.style.display='block';
      show(r.msg, true);
    } else {
      box.style.display='none';
      show(r.msg || '获取失败', false);
    }
  } catch(e) {
    show('操作异常: '+e.message, false);
  } finally {
    btn.disabled = false; btn.textContent = origText;
  }
}
async function sshKeyOnly(enable){
  const tgt = sshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = enable?'⏳ 启用中...':'⏳ 恢复中...';
  try {
    show((enable?'启用仅密钥登录':'恢复密码登录')+' 中(自动部署面板密钥并验证)...', true);
    const r = await api('/api/ssh_set_keyonly','POST',{target:tgt, enable});
    show(r.msg||'完成', r.ok);
    if(r.ok) setTimeout(()=>sshStatus(), 500);
  } catch(e) {
    show('操作异常: '+e.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}
// ---- 暴力破解防护 ----
function renderBans(elId, bans, kind){
  const box = document.getElementById(elId);
  if(!bans || bans.length === 0){
    box.innerHTML = '<span class="tag">'+t('bruteNoBan')+'</span>';
    return;
  }
  box.innerHTML = bans.map(b=>{
    const m = Math.ceil(b.remain/60);
    return `<div class="row" style="gap:8px"><b>${b.ip}</b> <span class="tag">剩余 ${b.remain}s (约 ${m} 分钟)</span> <a class="link" onclick="bruteUnban('${kind}','${b.ip}')">${t('bruteUnban')}</a></div>`;
  }).join('');
}
async function brutePanelList(){
  try {
    const r = await api('/api/ban_list');
    if(!r.ok){ show(r.msg||'查询失败', false); return; }
    const info = document.getElementById('brute_panel_info');
    info.textContent = `规则: ${r.window}秒内失败${r.max}次→封锁${r.ban_seconds}秒 | 当前被封 ${r.bans.length} 个 IP`;
    renderBans('brute_panel_bans', r.bans, 'panel');
  } catch(e) { show('查询异常: '+e.message, false); }
}
async function bruteCfgLoad(){
  try {
    const r = await api('/api/brute_get');
    if(r.ok){
      document.getElementById('brute_window').value = r.window;
      document.getElementById('brute_maxfail').value = r.max;
      document.getElementById('brute_ban').value = r.ban;
      document.getElementById('brute_cfg_current').textContent =
        `当前生效: 窗口 ${r.window} 秒 / 失败 ${r.max} 次 / 封锁 ${r.ban} 秒`;
    }
  } catch(e) {}
}
async function bruteCfgSave(){
  const w = parseInt(document.getElementById('brute_window').value, 10);
  const m = parseInt(document.getElementById('brute_maxfail').value, 10);
  const b = parseInt(document.getElementById('brute_ban').value, 10);
  if(!(w>=1 && w<=3600)){ show('统计窗口需在 1-3600 秒', false); return; }
  if(!(m>=1 && m<=1000)){ show('失败次数需在 1-1000', false); return; }
  if(!(b>=30 && b<=31536000)){ show('封锁时长需在 30-31536000 秒', false); return; }
  try {
    show('保存防护参数中...', true);
    const r = await api('/api/brute_set','POST',{window:w, max:m, ban:b});
    if(r.ok){
      document.getElementById('brute_cfg_current').textContent =
        `当前生效: 窗口 ${r.window} 秒 / 失败 ${r.max} 次 / 封锁 ${r.ban} 秒`;
      document.getElementById('brute_cfg_msg').textContent = r.msg || '';
    }
    show(r.msg || '已保存', r.ok);
  } catch(e) { show('操作异常: '+e.message, false); }
}
async function bruteUnban(kind, ip){
  try {
    if(kind === 'panel'){
      const r = await api('/api/ban_unban?ip='+encodeURIComponent(ip));
      show(r.msg, r.ok);
      if(r.ok) brutePanelList();
    } else {
      const tgt = document.getElementById('brute_ssh_target').value;
      const r = await api('/api/ssh_ban_unban?target='+tgt+'&ip='+encodeURIComponent(ip));
      show(r.msg, r.ok);
      if(r.ok) bruteSshStatus();
    }
  } catch(e) { show('操作异常: '+e.message, false); }
}
function bruteSshTarget(){ return document.getElementById('brute_ssh_target').value; }
async function bruteSshStatus(){
  const tgt = bruteSshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  try {
    const r = await api('/api/ssh_brute_status?target='+tgt);
    const info = document.getElementById('brute_ssh_info');
    if(!r.ok){ info.textContent = '查询失败: '+(r.msg||''); return; }
    let html = '';
    if(!r.installed){
      html = 'fail2ban: <b>'+t('bruteNotInst')+'</b>';
    } else {
      const st = r.active ? ('<b style="color:#27ae60">'+t('bruteEnabled')+'</b>') : ('<b style="color:#e74c3c">'+t('bruteDisabled')+'</b>');
      html = `fail2ban: ${st} | jail: ${r.jail_on?t('bruteSshOn'):t('bruteSshOff')} | 端口: ${r.port||'?'} | maxretry: ${r.maxretry??'?'} / findtime: ${r.findtime??'?'}s / bantime: ${r.bantime??'?'}s`;
    }
    info.innerHTML = html;
    renderBans('brute_ssh_bans', (r.banned||[]).map(ip=>({ip, remain:0})), 'ssh');
  } catch(e) { show('查询异常: '+e.message, false); }
}
async function bruteSshEnable(enable){
  const tgt = bruteSshTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  if(enable && !confirm(t('bruteEnableConfirm'))) return;
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = enable?'⏳ 启用中...':'⏳ 停用中...';
  try {
    show((enable?'启用 SSH 防护':'停用 SSH 防护')+' 中...', true);
    const r = await api('/api/ssh_brute_set','POST',{target:tgt, enable});
    show(r.msg||(enable?'已启用':'已停用'), r.ok);
    if(r.ok) setTimeout(()=>bruteSshStatus(), 800);
  } catch(e) { show('操作异常: '+e.message, false); }
  finally { btn.disabled = false; btn.textContent = origText; }
}
function copyText(id){
  const el = document.getElementById(id);
  const v = el.value || el.textContent || '';
  if(!v){ show('无内容', false); return; }
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(v).then(()=>show(t('copied'),true)).catch(()=>fallbackCopy(v));
  } else { fallbackCopy(v); }
}
// ---- SSH 密钥库 (列出 / 上传 / 删除) ----
async function loadSshKeys(){
  try{
    const r = await api('/api/ssh_keys');
    const list = document.getElementById('ssh_keys_list');
    const sel = document.getElementById('prov_ssh_key');
    if(!r.ok){ if(list) list.innerHTML='<span class="sub">密钥库读取失败</span>'; return; }
    const keys = r.keys||[];
    if(list){
      if(!keys.length){ list.innerHTML='<span class="sub">（暂无密钥，可在上方上传）</span>'; }
      else {
        list.innerHTML = keys.map(k=>`<div class="row" style="width:100%;gap:10px">
          <span class="tag">${k.name}</span>
          <span class="sub">${k.size}B · ${k.mtime}</span>
          <button class="sec" onclick="sshDeleteKey('${encodeURIComponent(k.name)}')" data-i18n="sshDelete">删除</button>
        </div>`).join('');
      }
    }
    if(sel){
      const cur = sel.value;
      sel.innerHTML = '<option value="">SSH密钥: 默认(面板密钥/密码)</option>' + keys.map(k=>`<option value="${k.name}">${k.name}</option>`).join('');
      if(cur) sel.value = cur;
    }
  }catch(e){}
}
async function sshUploadKey(){
  const name = document.getElementById('ssh_key_name').value.trim();
  const fileInput = document.getElementById('ssh_key_file');
  if(!name){ show('请输入密钥文件名', false); return; }
  if(!fileInput.files.length){ show('请选择密钥文件', false); return; }
  const f = fileInput.files[0];
  const buf = await f.arrayBuffer();
  const b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
  show('上传密钥中...', true);
  const r = await api('/api/ssh_key_upload','POST',{name, content:b64});
  show(r.msg, r.ok);
  if(r.ok){ document.getElementById('ssh_key_name').value=''; fileInput.value=''; loadSshKeys(); }
}
async function sshDeleteKey(name){
  name = decodeURIComponent(name);
  if(!confirm('确认删除密钥 '+name+' ? (若正被出口使用将拒绝)')) return;
  const r = await api('/api/ssh_key_delete','POST',{name});
  show(r.msg, r.ok);
  if(r.ok) loadSshKeys();
}
// ---- ⑩ 备份与恢复 ----
function reloadAll(){
  loadState();
  try{ loadSshKeys(); }catch(e){}
  try{ routeLoad(); }catch(e){}
}
async function backupExport(){
  show('正在生成备份...', true);
  try{
    const r = await fetch(BASE + '/api/backup/export');
    if(!r.ok){ show('备份下载失败 (HTTP '+r.status+')', false); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'xcfui_backup_' + new Date().toISOString().slice(0,19).replace(/[:T-]/g,'') + '.json';
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    show('备份已生成, 浏览器开始下载', true);
    try{ backupListLoad(); }catch(e){}
  }catch(e){ show('备份失败: '+e.message, false); }
}
async function backupUpload(){
  const f = document.getElementById('backup_file');
  if(!f.files.length){ show(t('backupNoFile'), false); return; }
  const buf = await f.files[0].arrayBuffer();
  const b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
  show('上传备份中...', true);
  const r = await api('/api/backup/upload','POST',{content:b64});
  show(r.msg, r.ok);
  if(r.ok){
    const m = document.getElementById('backup_msg');
    m.textContent = (r.created ? (t('backupTime')+r.created+' · ') : '') + t('backupReady');
  }
}
async function backupRestore(){
  if(!confirm(t('backupConfirmRestore'))) return;
  show('恢复中...', true);
  const r = await api('/api/backup/restore','POST',{});
  show(r.msg, r.ok);
  if(r.ok){ document.getElementById('backup_msg').textContent = t('backupRestored'); reloadAll(); }
}
async function backupDefaultSave(){
  if(!confirm(t('backupConfirmDefault'))) return;
  show('保存出厂默认中...', true);
  const r = await api('/api/backup/default_save','POST',{});
  show(r.msg, r.ok);
}
async function backupDefaultRestore(){
  if(!confirm(t('backupConfirmImport'))) return;
  show('导入出厂默认中...', true);
  const r = await api('/api/backup/default_restore','POST',{});
  show(r.msg, r.ok);
  if(r.ok) reloadAll();
}
async function backupListLoad(){
  try{
    const r = await api('/api/backup/list');
    const tb = document.getElementById('backup_saved_list');
    const msg = document.getElementById('backup_saved_msg');
    if(!r.ok){ msg.textContent = r.msg; tb.innerHTML=''; return; }
    msg.textContent = '';
    if(!r.files.length){
      tb.innerHTML = '<tr><td colspan="4" style="color:#888;padding:8px;text-align:center" data-i18n="backupEmpty">'+t('backupEmpty')+'</td></tr>';
      return;
    }
    tb.innerHTML = r.files.map(f =>
      '<tr><td>'+escAttr(f.name)+'</td><td>'+_fmtSize(f.size)+'</td><td>'+escAttr(f.time)+'</td>'+
      '<td><a class="link" onclick="backupDownload(\''+escAttr(f.name)+'\')">'+t('machineDownload')+'</a> '+
      '<a class="link" onclick="backupRestoreFile(\''+escAttr(f.name)+'\')">'+t('backupRestore')+'</a> '+
      '<a class="link" style="color:var(--err)" onclick="backupDelete(\''+escAttr(f.name)+'\')">'+t('machineDelete')+'</a></td></tr>'
    ).join('');
  }catch(e){ show('加载备份列表异常: '+e.message, false); }
}
async function backupDownload(fname){
  show('正在下载...', true);
  try{
    const r = await fetch(BASE + '/api/backup/download?file='+encodeURIComponent(fname));
    if(!r.ok){ show('下载失败 (HTTP '+r.status+')', false); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download=fname;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    show(t('backupRestored'), true);
  }catch(e){ show('下载失败: '+e.message, false); }
}
async function backupDelete(fname){
  if(!confirm(t('backupConfirmDelete')+': '+fname)) return;
  const r = await api('/api/backup/delete','POST',{file:fname});
  show(r.msg, r.ok);
  if(r.ok) backupListLoad();
}
async function backupRestoreFile(fname){
  if(!confirm(t('backupConfirmRestore')+'\n\n'+fname)) return;
  show('恢复中: '+fname, true);
  try{
    const resp = await fetch(BASE + '/api/backup/download?file='+encodeURIComponent(fname));
    if(!resp.ok){ show('下载失败 (HTTP '+resp.status+')', false); return; }
    const buf = await resp.arrayBuffer();
    const b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
    const ur = await api('/api/backup/upload','POST',{content:b64,name:fname});
    if(!ur.ok){ show(ur.msg, false); return; }
    const rr = await api('/api/backup/restore','POST',{});
    show(rr.msg, rr.ok);
    if(rr.ok){ document.getElementById('backup_msg').textContent = t('backupRestored'); reloadAll(); }
  }catch(e){ show('恢复失败: '+e.message, false); }
}
// ---- ⑪ 整机完整备份 ----
function _fmtSize(n){
  n = Number(n)||0;
  if(n < 1024) return n + ' B';
  if(n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if(n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}
function machineTarget(){ return document.getElementById('machine_target').value; }
function _machineStateText(job){
  if(!job || job.state==='idle') return t('machineStateIdle');
  if(job.state==='running') return t('machineStateRunning');
  if(job.state==='done') return t('machineStateDone') + (job.filename? (': '+job.filename):'') + (job.rc===1? ' ('+t('machineRcNote')+')':'');
  if(job.state==='error') return t('machineStateError') + (job.error? (': '+job.error):'');
  return job.state;
}
async function machineLoad(){
  const tgt = machineTarget();
  const stEl = document.getElementById('machine_status');
  const tb = document.getElementById('machine_list');
  stEl.innerHTML='<span style="color:var(--acc);animation:spin 0.8s linear infinite;display:inline-block;margin-right:4px">⟳</span> '+t('machineLoading')+'...';
  stEl.style.opacity='0.7';
  tb.innerHTML='';
  try{
    const r = await api('/api/machine_backup/list?target='+tgt);
    stEl.style.opacity='';
    if(!r.ok){ stEl.textContent = r.msg; return; }
    stEl.textContent = _machineStateText(r.job);
    tb.innerHTML = '';
    if(!r.files || !r.files.length){
      tb.insertAdjacentHTML('beforeend', '<tr><td colspan="4" class="muted">'+t('machineNoBackup')+'</td></tr>');
      return;
    }
    for(const f of r.files){
      const dl = BASE + '/api/machine_backup/download?target='+tgt+'&file='+encodeURIComponent(f.name);
      tb.insertAdjacentHTML('beforeend', `<tr>
        <td>${escAttr(f.name)}</td>
        <td>${_fmtSize(f.size)}</td>
        <td>${escAttr(f.mtime)}</td>
        <td>
          <a class="link" href="${dl}" download="${escAttr(f.name)}">${t('machineDownload')}</a>
          <a class="link" onclick="machineDelete('${escAttr(f.name)}')">${t('machineDelete')}</a>
        </td></tr>`);
    }
  }catch(e){ show('操作异常: '+e.message, false); }
}
async function machineStart(){
  const tgt = machineTarget();
  if(!tgt){ show('请先选择目标服务器', false); return; }
  const btn = event.currentTarget;
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳...';
  try{
    const r = await api('/api/machine_backup/start','POST',{target:tgt});
    show(r.msg, r.ok);
    if(r.ok){ document.getElementById('machine_msg').textContent = t('machineStarted'); machineLoad(); }
  }catch(e){ show('操作异常: '+e.message, false); }
  finally{ btn.disabled = false; btn.textContent = origText; }
}
async function machineDelete(name){
  if(!confirm(t('machineDelete')+' '+name+'?')) return;
  const tgt = machineTarget();
  try{
    show('删除中...', true);
    const r = await api('/api/machine_backup/delete','POST',{target:tgt, file:name});
    show(r.msg, r.ok);
    if(r.ok) machineLoad();
  }catch(e){ show('操作异常: '+e.message, false); }
}
// ---- ⑧ 智能分流规则 (按域名/IP/端口) ----
let _routeRules = [];
let _routeOutbounds = [];
async function routeLoad(){
  try{
    const r = await api('/api/routing_rules');
    if(!r.ok) return;
    _routeRules = r.rules || [];
    _routeOutbounds = r.outbounds || ['direct','block'];
    document.getElementById('route_enabled').checked = !!r.enabled;
    const geo = document.getElementById('route_geoip');
    if(geo) geo.textContent = r.geoip_available ? 'GeoIP.dat 已就绪' : 'GeoIP.dat 缺失 (GeoIP 规则不可用)';
    document.getElementById('route_box').style.display = r.enabled ? 'block' : 'none';
    renderRouteList(_routeRules);
  }catch(e){}
}
function routeToggle(){
  document.getElementById('route_box').style.display = document.getElementById('route_enabled').checked ? 'block' : 'none';
}
function renderRouteList(rules){
  _routeRules = rules;
  const box = document.getElementById('route_list');
  if(!box) return;
  box.innerHTML = '';
  const types = [['domain_suffix','域名后缀(domain)'],['domain_full','完整域名(full)'],
                 ['keyword','关键词'],['ip','IP / CIDR'],['geoip','GeoIP'],['port','端口']];
  rules.forEach((r,i)=>{
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:6px;margin:4px 0;align-items:center';
    const sel = document.createElement('select');
    types.forEach(t=>{ const o=document.createElement('option'); o.value=t[0]; o.textContent=t[1]; if(t[0]===r.type)o.selected=true; sel.appendChild(o); });
    sel.onchange = ()=>{ r.type = sel.value; };
    const val = document.createElement('input');
    val.value = r.value || ''; val.placeholder = '匹配值 (如 tiktok.com / 1.2.3.0/24)'; val.style.minWidth='180px';
    val.oninput = ()=>{ r.value = val.value; };
    const arrow = document.createElement('span'); arrow.textContent = '→';
    const ob = document.createElement('select');
    _routeOutbounds.forEach(t=>{ const o=document.createElement('option'); o.value=t; o.textContent=t; if(t===r.outbound)o.selected=true; ob.appendChild(o); });
    ob.onchange = ()=>{ r.outbound = ob.value; };
    const en = document.createElement('input'); en.type='checkbox'; en.title='启用'; en.checked=r.enabled!==false; en.style.width='16px';
    en.onchange = ()=>{ r.enabled = en.checked; };
    const up = document.createElement('button'); up.textContent='↑'; up.onclick=()=>routeMove(i,-1);
    const dn = document.createElement('button'); dn.textContent='↓'; dn.onclick=()=>routeMove(i,1);
    const del = document.createElement('button'); del.className='sec'; del.textContent='✕'; del.onclick=()=>{ _routeRules.splice(i,1); renderRouteList(_routeRules); };
    [sel,val,arrow,ob,en,up,dn,del].forEach(e=>row.appendChild(e));
    box.appendChild(row);
  });
}
function routeAdd(){ _routeRules.push({type:'domain_suffix',value:'',outbound:(_routeOutbounds[0]||'direct'),enabled:true}); renderRouteList(_routeRules); }
function routeMove(i,d){ const a=_routeRules; const j=i+d; if(j<0||j>=a.length) return; const t=a[i]; a[i]=a[j]; a[j]=t; renderRouteList(a); }
async function routeSave(){
  const rules = _routeRules.map(r=>({type:r.type, value:(r.value||'').trim(), outbound:r.outbound, enabled:r.enabled!==false}));
  const r = await api('/api/routing_rules','POST',{enabled:document.getElementById('route_enabled').checked, rules});
  document.getElementById('route_msg').textContent = r.msg || (r.ok?'ok':'fail');
  show(r.msg, r.ok);
  if(r.ok) routeLoad();
}
applyLang();
loadState();
loadSshKeys();
routeLoad();
initNav();
machineLoad();
bruteCfgLoad();
try{ backupListLoad(); }catch(e){}
</script>
</body>
</html>
"""


def entry_token():
    try:
        return load_state().get("entry_token") or "aa888888"
    except Exception:
        return "aa888888"


# ---- 登录暴力破解防护 (应用层限流 + 持久化封禁) ----
BAN_FILE = os.path.join(BASE, "ban.json")
LOGIN_FAIL = {}      # ip -> [失败时间戳...]  (内存, 仅统计当前窗口)
LOGIN_BAN = {}       # ip -> 解封时间戳(unix) (持久化, 重启仍生效)
BRUTE_CFG_FILE = os.path.join(BASE, "brute_config.json")
BRUTE_WINDOW = 60    # 统计窗口(秒)  (运行时可被面板修改)
BRUTE_MAXFAIL = 17   # 窗口内允许的最大失败次数
BRUTE_BAN = 17200    # 触发后封锁时长(秒)

def load_brute_config():
    global BRUTE_WINDOW, BRUTE_MAXFAIL, BRUTE_BAN
    try:
        d = json.load(open(BRUTE_CFG_FILE, encoding="utf-8"))
        BRUTE_WINDOW = int(d.get("window", 60))
        BRUTE_MAXFAIL = int(d.get("max", 17))
        BRUTE_BAN = int(d.get("ban", 17200))
    except Exception:
        pass

def save_brute_config(window, maxfail, ban):
    global BRUTE_WINDOW, BRUTE_MAXFAIL, BRUTE_BAN
    BRUTE_WINDOW = int(window); BRUTE_MAXFAIL = int(maxfail); BRUTE_BAN = int(ban)
    try:
        json.dump({"window": BRUTE_WINDOW, "max": BRUTE_MAXFAIL, "ban": BRUTE_BAN},
                  open(BRUTE_CFG_FILE, "w", encoding="utf-8"))
    except Exception:
        pass

load_brute_config()

def _load_ban():
    try:
        return json.load(open(BAN_FILE, encoding="utf-8"))
    except Exception:
        return {}

def _save_ban():
    try:
        json.dump(LOGIN_BAN, open(BAN_FILE, "w", encoding="utf-8"))
    except Exception:
        pass

LOGIN_BAN = _load_ban()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _api_path(self):
        token = entry_token()
        p = self.path.split("?")[0]
        prefix = f"/{token}/api/"
        if p.startswith(prefix):
            return p[len(token) + 1:]
        return None

    def _auth(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            self._record_fail()
            return False
        try:
            dec = base64.b64decode(h[6:]).decode()
            user, pw = dec.split(":", 1)
            st = load_state()
            if user == st["admin_user"] and pw == st["admin_pass"]:
                LOGIN_FAIL.pop(self.client_ip(), None)
                return True
            self._record_fail()
            return False
        except Exception:
            self._record_fail()
            return False

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _is_api(self):
        return self._api_path() is not None

    def _send_html(self, code, html):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_ban(self):
        """本 IP 处于封锁期则拒绝请求(不弹登录框)。"""
        ip = self.client_ip()
        bu = LOGIN_BAN.get(ip)
        if bu and bu > time.time():
            remain = int(bu - time.time())
            if self._is_api():
                self._send(403, {"ok": False, "msg": "该 IP 因多次登录失败已被封锁, 剩余 %d 秒" % remain})
            else:
                self._send_html(403,
                    "<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
                    "<title>访问被拒绝</title></head><body style='font-family:system-ui,sans-serif;"
                    "max-width:520px;margin:80px auto;padding:0 20px;color:#333'>"
                    "<h2>访问被拒绝</h2>"
                    "<p>该 IP 因多次登录失败已被临时封锁, 剩余约 %d 秒 (约 %d 分钟)。</p>"
                    "<p style='color:#888;font-size:13px'>防护规则: %d 秒内失败 %d 次即封锁 %d 秒。</p>"
                    "</body></html>" % (remain, (remain + 59) // 60, BRUTE_WINDOW, BRUTE_MAXFAIL, BRUTE_BAN))
            return True
        return False

    def _record_fail(self):
        global LOGIN_FAIL, LOGIN_BAN
        ip = self.client_ip()
        now = time.time()
        lst = LOGIN_FAIL.get(ip, [])
        lst = [t for t in lst if now - t < BRUTE_WINDOW]
        lst.append(now)
        if len(lst) >= BRUTE_MAXFAIL:
            LOGIN_BAN[ip] = now + BRUTE_BAN
            LOGIN_FAIL.pop(ip, None)
            _save_ban()
        else:
            LOGIN_FAIL[ip] = lst

    def _do_ban_list(self):
        now = time.time()
        bans = [{"ip": ip, "remain": int(bu - now)} for ip, bu in LOGIN_BAN.items() if bu > now]
        fails = {ip: len([t for t in lst if now - t < BRUTE_WINDOW]) for ip, lst in LOGIN_FAIL.items()}
        self._send(200, {"ok": True, "bans": bans, "fails": fails,
                         "window": BRUTE_WINDOW, "max": BRUTE_MAXFAIL, "ban_seconds": BRUTE_BAN})

    def _do_ban_unban(self):
        q = {}
        try:
            from urllib.parse import parse_qs
            q = parse_qs(self.path.split("?", 1)[1])
        except Exception:
            pass
        ip = (q.get("ip", [""])[0] or "").strip()
        if not ip:
            self._send(200, {"ok": False, "msg": "缺少 ip 参数"}); return
        if LOGIN_BAN.pop(ip, None) is not None:
            _save_ban()
            self._send(200, {"ok": True, "msg": "已解封面板登录封锁: " + ip}); return
        self._send(200, {"ok": True, "msg": "该 IP 未被封锁: " + ip}); return

    def _send(self, code, obj, ctype="application/json"):
        body = json.dumps(obj, ensure_ascii=False).encode() if isinstance(obj, (dict, list)) else obj.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ap = self._api_path()
        # 封锁管理接口: 需正确鉴权, 允许管理员自救(绕过 IP 封锁)
        if ap == "/api/ban_list":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            self._do_ban_list(); return
        if ap == "/api/ban_unban":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            self._do_ban_unban(); return
        # IP 封锁检查(应用层暴力破解防护)
        if self._check_ban():
            return
        token = entry_token()
        p = self.path.split("?")[0]
        p_base = p.rstrip("/") or "/"
        if p_base == f"/{token}":
            if not self._auth():
                self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="x-cfui"'); self.end_headers(); return
            self._send(200, PAGE, "text/html")
            return
        ap = self._api_path()
        if ap == "/api/state":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            st = load_state()
            pub = {k: v for k, v in st.items() if k != "admin_pass"}
            for ex in pub.get("exits", []):
                ex.pop("ssh_pass", None)
            self._send(200, pub)
            return
        if ap == "/api/bbr_status":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            q = {}
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?",1)[1])
            except Exception:
                pass
            idx = q.get("index", [None])[0]
            if idx is not None:
                try:
                    i = int(idx); st = load_state()
                    if 0 <= i < len(st["exits"]):
                        ex = st["exits"][i]
                        res = bbr_status_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22), key=ex.get("ssh_key"))
                        res["host"] = ex["address"]; res["name"] = ex["name"]
                        self._send(200, res); return
                except Exception as e:
                    self._send(200, {"ok":False,"msg":str(e)}); return
            res = bbr_status(); res["host"] = CN_ADDR; res["name"] = "入口服务器"
            self._send(200, res)
            return
        if ap == "/api/firewall":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?",1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            if tgt == "entry" or tgt == "cn":
                res = fw_status_local()
            else:
                try:
                    i = int(q.get("index", [0])[0]); st = load_state(); ex = st["exits"][i]
                except Exception as e:
                    self._send(200, {"ok": False, "msg": "exit index invalid: "+str(e)}); return
                res = fw_status_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22), key=ex.get("ssh_key"))
                res["host"] = ex["address"]; res["name"] = ex["name"]
            self._send(200, res)
            return
        if ap == "/api/autostart":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?",1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            if tgt == "entry" or tgt == "cn":
                self._send(200, autostart_local())
            else:
                try:
                    i = int(q.get("index", [0])[0]); st = load_state(); ex = st["exits"][i]
                except Exception as e:
                    self._send(200, {"ok": False, "msg": "exit index invalid: "+str(e)}); return
                res = autostart_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22), key=ex.get("ssh_key"))
                res["host"] = ex["address"]; res["name"] = ex["name"]
                self._send(200, res)
            return
        if ap == "/api/autostart_all":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            res = [autostart_local()]
            st = load_state()
            for i, ex in enumerate(st["exits"]):
                # 优先用面板管理密钥(-i PANEL_KEY), 即使 state 中未存 ssh_pass 也能管理仅密钥登录的服务器
                r = autostart_remote(ex["address"], ex.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22), key=ex.get("ssh_key"))
                r["host"] = ex["address"]; r["name"] = ex["name"]
                res.append(r)
            self._send(200, res)
            return
        if ap == "/api/brute_get":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            self._send(200, {"ok": True, "window": BRUTE_WINDOW, "max": BRUTE_MAXFAIL, "ban": BRUTE_BAN})
            return
        if ap == "/api/ssh_brute_status":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            self._send(200, ssh_brute_status(tgt))
            return
        if ap == "/api/ssh_ban_unban":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            ip = (q.get("ip", [""])[0] or "").strip()
            self._send(200, ssh_ban_unban(tgt, ip))
            return
        if ap == "/api/qr":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                import io, base64, segno
                q = parse_qs(self.path.split("?",1)[1])
                text = q.get("text", [""])[0]
                buf = io.BytesIO()
                segno.make(text, error="m").save(buf, kind="png", scale=4, border=2)
                data = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            except Exception as e:
                self._send(404, {"ok":False,"msg":str(e)}); return
        if ap == "/api/ssh_status":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            kind, ex = resolve_target(tgt)
            if kind is None:
                self._send(200, {"ok": False, "msg": "未知服务器目标"}); return
            res = ssh_status(tgt)
            res["host"] = CN_ADDR if kind == "entry" else (ex.get("address") if ex else tgt)
            res["name"] = "入口服务器" if tgt == "entry" else (ex.get("name", tgt) if ex else tgt)
            self._send(200, res)
            return
        if ap == "/api/ports":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            result = {}
            st = load_state()
            for tgt in ["entry"] + [e["tag"] for e in st.get("exits", [])]:
                kind, ex = resolve_target(tgt)
                if kind is None:
                    result[tgt] = {"ok": False, "msg": "未知服务器目标"}
                    continue
                r = get_listening_ports(tgt)
                r["host"] = CN_ADDR if kind == "entry" else (ex.get("address") if ex else tgt)
                r["name"] = "入口服务器" if tgt == "entry" else (ex.get("name", tgt) if ex else tgt)
                result[tgt] = r
            self._send(200, {"ok": True, "servers": result})
            return
        if ap == "/api/ssh_keys":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            self._send(200, list_ssh_keys())
            return
        if ap == "/api/ssh_download_key":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                q = {}
            tgt = q.get("target", ["entry"])[0]
            res = ssh_download_key(tgt)
            self._send(200, res)
            return
        if ap == "/api/routing_rules":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            st = load_state()
            geoip_available = geoip_is_valid()
            self._send(200, {
                "ok": True,
                "enabled": st.get("smart_routing", False),
                "rules": st.get("routing_rules", []),
                "outbounds": [ex["tag"] for ex in st["exits"]] + ["direct", "block"],
                "exits": [{"tag": ex["tag"], "name": ex["name"]} for ex in st["exits"]],
                "geoip_available": geoip_available,
            })
            return
        if ap == "/api/backup/export":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            data = _collect_backup()
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            fname = "xcfui_backup_%s.json" % time.strftime("%Y%m%d_%H%M%S")
            # 同时保存到服务器备份目录
            try:
                os.makedirs(BACKUP_DIR, exist_ok=True)
                save_path = os.path.join(BACKUP_DIR, fname)
                with open(save_path, "wb") as f:
                    f.write(body)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % fname)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if ap == "/api/backup/list":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            os.makedirs(BACKUP_DIR, exist_ok=True)
            files = []
            _skip = ("default_backup.json", "uploaded_backup.json")
            for fn in sorted(os.listdir(BACKUP_DIR), reverse=True):
                if not fn.endswith(".json") or fn in _skip:
                    continue
                fp = os.path.join(BACKUP_DIR, fn)
                try:
                    st = os.stat(fp)
                    files.append({
                        "name": fn,
                        "size": st.st_size,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                    })
                except Exception:
                    continue
            self._send(200, {"ok": True, "files": files})
            return
        if ap == "/api/backup/download":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            q = {}
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                pass
            fname = q.get("file", [""])[0]
            if not fname or ".." in fname or "/" in fname or not fname.endswith(".json"):
                self._send(400, {"ok": False, "msg": "非法文件名"}); return
            fp = os.path.join(BACKUP_DIR, fname)
            if not os.path.isfile(fp):
                self._send(404, {"ok": False, "msg": "文件不存在"}); return
            with open(fp, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % fname)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if ap == "/api/machine_backup/list":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            q = {}
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                pass
            tgt = q.get("target", ["entry"])[0]
            res = machine_backup_list(tgt)
            res["target"] = tgt
            res["job"] = machine_jobs.get(tgt, {"state": "idle"})
            self._send(200, res)
            return
        if ap == "/api/machine_backup/download":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            q = {}
            try:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1])
            except Exception:
                pass
            tgt = q.get("target", ["entry"])[0]
            fname = q.get("file", [""])[0]
            machine_backup_stream(tgt, fname, self)
            return
        self._send(404, {"ok": False, "msg": "not found"})

    def do_POST(self):
        # 面板登录封锁管理接口(解封): 需正确鉴权后绕过 IP 封锁
        if self._api_path() == "/api/ban_unban":
            if not self._auth():
                self._send(401, {"ok": False, "msg": "未授权"}); return
            self._do_ban_unban(); return
        # IP 封锁检查(应用层暴力破解防护)
        if self._check_ban():
            return
        if not self._auth():
            self._send(401, {"ok": False, "msg": "未授权"}); return
        p = self._api_path()
        if p is None:
            self._send(404, {"ok": False, "msg": "not found"}); return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except Exception:
            data = {}
        st = load_state()

        if p == "/api/exit":
            tag = "exit-" + secrets.token_hex(3)
            st["exits"].append({
                "tag": tag, "name": data.get("name", "节点"),
                "address": data["address"], "port": int(data["port"]),
                "uuid": data.get("uuid") or str(__import__("uuid").uuid4()),
                "relay_security": "tls", "pushed_relay": None, "bbr": False,
            })
            save_state(st)
            self._send(200, {"ok": True, "msg": f"已添加出口 {data.get('name')} (默认中继TLS), 记得应用配置"})

        elif p == "/api/inbound":
            if any(int(b["port"]) == int(data["port"]) for b in st["inbounds"]):
                self._send(200, {"ok": False, "msg": f"端口 {data['port']} 已存在"}); return
            sec = data.get("security", "reality")
            ib = {"port": int(data["port"]), "tag": "entry-" + str(data["port"]),
                  "name": data.get("name", "端口" + str(data["port"])), "exit": data["exit"], "security": sec}
            if sec == "reality":
                pk, pubk = gen_reality_keypair()
                sni = data.get("sni") or "www.apple.com"
                ib["reality"] = {"serverName": sni, "privateKey": pk, "publicKey": pubk,
                                 "shortId": gen_short_id(), "dest": sni + ":443", "spiderX": "/"}
            st["inbounds"].append(ib)
            save_state(st)
            self._send(200, {"ok": True, "msg": f"已添加入口 {data['port']} ({sec}), 记得应用配置"})

        elif p == "/api/exit_rename":
            try:
                i = int(data.get("index", -1))
            except (ValueError, TypeError):
                self._send(200, {"ok": False, "msg": "索引无效"}); return
            name = (data.get("name", "") or "").strip()
            if not name:
                self._send(200, {"ok": False, "msg": "名称不能为空"}); return
            if not (0 <= i < len(st["exits"])):
                self._send(200, {"ok": False, "msg": "出口索引越界"}); return
            old = st["exits"][i].get("name", "")
            st["exits"][i]["name"] = name
            save_state(st)
            self._send(200, {"ok": True, "msg": f"出口名称已修改: {old} → {name} (显示名称, 无需重应用配置)"})

        elif p == "/api/inbound_rename":
            try:
                i = int(data.get("index", -1))
            except (ValueError, TypeError):
                self._send(200, {"ok": False, "msg": "索引无效"}); return
            name = (data.get("name", "") or "").strip()
            if not name:
                self._send(200, {"ok": False, "msg": "名称不能为空"}); return
            if not (0 <= i < len(st["inbounds"])):
                self._send(200, {"ok": False, "msg": "入口索引越界"}); return
            old = st["inbounds"][i].get("name", "")
            st["inbounds"][i]["name"] = name
            save_state(st)
            self._send(200, {"ok": True, "msg": f"入口线路名称已修改: {old} → {name} (显示名称, 无需重应用配置)"})

        elif p == "/api/client_uuid":
            st["client_uuid"] = data["uuid"]
            save_state(st)
            self._send(200, {"ok": True, "msg": "客户端UUID已保存, 记得应用配置"})

        elif p == "/api/client_fp":
            fp = data.get("fp", "chrome")
            st["client_fp"] = fp
            save_state(st)
            self._send(200, {"ok": True, "msg": "客户端伪装指纹已保存: " + fp})

        elif p == "/api/public_host":
            action = (data.get("action", "") or "").strip()
            h = (data.get("host", "") or "").strip()
            hosts = st.get("public_hosts", [])
            if action == "delete":
                idx = data.get("index")
                if idx is not None:
                    try:
                        idx = int(idx)
                        if 0 <= idx < len(hosts):
                            removed = hosts.pop(idx)
                            st["public_hosts"] = hosts
                            save_state(st)
                            self._send(200, {"ok": True, "msg": "已删除地址: " + removed})
                            return
                    except (ValueError, TypeError):
                        pass
                self._send(200, {"ok": False, "msg": "无效的索引"}); return
            # default: add
            if not h:
                self._send(200, {"ok": False, "msg": "域名/地址不能为空"}); return
            if h in hosts:
                self._send(200, {"ok": False, "msg": "该地址已存在: " + h}); return
            hosts.append(h)
            st["public_hosts"] = hosts
            save_state(st)
            self._send(200, {"ok": True, "msg": "已添加地址: " + h})

        elif p == "/api/site_settings":
            title = (data.get("site_title", "") or "").strip()
            footer = (data.get("site_footer", "") or "").strip()
            st["site_title"] = title or "x-cfui"
            st["site_footer"] = footer or "QQ: 123008"
            save_state(st)
            self._send(200, {"ok": True, "msg": "网站设置已保存", "site_title": st["site_title"], "site_footer": st["site_footer"]})

        elif p == "/api/ssh_set_port":
            tgt = data.get("target", "entry")
            res = ssh_set_port(tgt, data.get("port"))
            self._send(200, res)

        elif p == "/api/ssh_gen_key":
            tgt = data.get("target", "entry")
            res = ssh_gen_key(tgt)
            self._send(200, res)

        elif p == "/api/ssh_set_keyonly":
            tgt = data.get("target", "entry")
            enable = bool(data.get("enable"))
            res = ssh_set_keyonly(tgt, enable)
            self._send(200, res)

        elif p == "/api/apply":
            ok, msg = apply_config(st)
            self._send(200, {"ok": ok, "msg": msg})

        elif p == "/api/provision":
            name = data.get("name", "").strip()
            addr = data.get("address", "").strip()
            if not name or not addr:
                self._send(200, {"ok": False, "msg": "名称和服务器IP必填"}); return
            ex = next((e for e in st["exits"] if e["address"] == addr), None)
            if not ex:
                import uuid as _uuid
                ex = {
                    "tag": "exit-" + secrets.token_hex(3), "name": name,
                    "address": addr, "port": 10443, "uuid": str(_uuid.uuid4()),
                    "relay_security": "tls", "pushed_relay": None, "bbr": False,
                    "ssh_user": data.get("ssh_user", "root"),
                    "ssh_pass": data.get("ssh_pass", ""),
                    "ssh_port": int(data.get("ssh_port", 22)),
                    "ssh_key": data.get("ssh_key", ""),
                }
                st["exits"].append(ex)
            else:
                ex["ssh_user"] = data.get("ssh_user", "root")
                ex["ssh_pass"] = data.get("ssh_pass", "")
                ex["ssh_port"] = int(data.get("ssh_port", 22))
                ex["ssh_key"] = data.get("ssh_key", ex.get("ssh_key", ""))
                ex["relay_security"] = ex.get("relay_security", "tls")
                ex["pushed_relay"] = None
            save_state(st)
            ok, log = provision_exit(ex, data.get("ssh_pass", ""), int(data.get("ssh_port", 22)),
                                     data.get("ssh_user", "root"), key=ex.get("ssh_key"))
            if ok:
                ex["pushed_relay"] = ex["relay_security"]
                ex["bbr"] = True
                save_state(st)
                autostart = autostart_remote(ex["address"], data.get("ssh_pass",""), ex.get("ssh_user","root"), ex.get("ssh_port",22), key=ex.get("ssh_key"))
                self._send(200, {"ok": True,
                                 "msg": "部署成功(已装Xray+TLS+BBR) 并已完成开机自启核验",
                                 "log": log, "autostart": autostart})
            else:
                self._send(200, {"ok": False, "msg": "部署失败", "log": log})

        elif p == "/api/bbr":
            i = int(data.get("index", -1))
            if not (0 <= i < len(st["exits"])):
                self._send(200, {"ok": False, "msg": "出口索引无效"}); return
            ex = st["exits"][i]
            user = data.get("ssh_user") or ex.get("ssh_user", "root")
            pw = data.get("ssh_pass") or ex.get("ssh_pass", "")
            sport = data.get("ssh_port") or ex.get("ssh_port", 22)
            key = data.get("ssh_key") or ex.get("ssh_key", "")
            if not pw and not key and not os.path.exists(PANEL_KEY):
                self._send(200, {"ok": False, "msg": "缺少 SSH 密码或密钥, 请在弹窗中输入"}); return
            ex["ssh_key"] = key
            ok, log = enable_bbr(ex["address"], pw, user, sport, key=key)
            if ok:
                ex["bbr"] = True
                ex["ssh_user"] = user
                ex["ssh_pass"] = pw
                ex["ssh_port"] = sport
                save_state(st)
                self._send(200, {"ok": True, "msg": f"{ex['name']} BBR 已开启: {log.strip()}", "log": log})
            else:
                self._send(200, {"ok": False, "msg": f"{ex['name']} BBR 开启失败", "log": log})

        elif p == "/api/firewall":
            tgt = data.get("target", "entry")
            action = data.get("action")
            if tgt == "entry" or tgt == "cn":
                extra = [load_state().get("cn_ssh_port", 22)] if action == "enable" else None
                if action in ("enable", "disable"):
                    res = fw_operate_local(action, extra_ports=extra)
                else:
                    res = fw_operate_local(action, data.get("port"), data.get("proto", "tcp"))
                self._send(200, res)
            else:
                i = int(data.get("index", -1))
                if not (0 <= i < len(st["exits"])):
                    self._send(200, {"ok": False, "msg": "出口索引无效"}); return
                ex = st["exits"][i]
                pw = data.get("ssh_pass") or ex.get("ssh_pass", "")
                key = data.get("ssh_key") or ex.get("ssh_key", "")
                if not pw and not key and not os.path.exists(PANEL_KEY):
                    self._send(200, {"ok": False, "msg": "缺少 SSH 密码或密钥, 请在弹窗中输入"}); return
                ex["ssh_key"] = key
                user = data.get("ssh_user") or ex.get("ssh_user", "root")
                sport = data.get("ssh_port") or ex.get("ssh_port", 22)
                extra = [ex.get("ssh_port", 22)] if action == "enable" else None
                if action in ("enable", "disable"):
                    res = fw_operate_remote(ex["address"], pw, action, None, "tcp", user, sport, extra, key=key)
                else:
                    res = fw_operate_remote(ex["address"], pw, action, data.get("port"), data.get("proto", "tcp"), user, sport, extra, key=key)
                res["host"] = ex["address"]; res["name"] = ex["name"]
                self._send(200, res)

        elif p == "/api/firewall_harden":
            # 一键加固: 放行三台服务器正在监听的全部端口, 拒绝其余端口
            res = fw_harden_all()
            self._send(200, {"ok": True, "results": res})

        elif p == "/api/security":
            new_user = (data.get("admin_user") or "").strip()
            new_pass = data.get("admin_pass") or ""
            new_token = (data.get("entry_token") or "").strip()
            if new_user:
                st["admin_user"] = new_user
            if new_pass:
                if len(new_pass) < 6:
                    self._send(200, {"ok": False, "msg": "密码至少 6 位"}); return
                st["admin_pass"] = new_pass
            if new_token:
                if not new_token.isalnum():
                    self._send(200, {"ok": False, "msg": "密令只能为字母数字"}); return
                st["entry_token"] = new_token
            save_state(st)
            self._send(200, {"ok": True,
                             "msg": "安全设置已保存" + (f" (新入口: /{st['entry_token']})" if new_token else ""),
                             "entry_token": st["entry_token"]})

        elif p == "/api/ssh_key_upload":
            name = (data.get("name") or "").strip()
            content = data.get("content", "")
            if not name or not content:
                self._send(200, {"ok": False, "msg": "密钥文件名与内容均必填"}); return
            res = upload_ssh_key(name, content)
            self._send(200, res)
            return
        elif p == "/api/ssh_key_delete":
            name = (data.get("name") or "").strip()
            if not name:
                self._send(200, {"ok": False, "msg": "密钥名必填"}); return
            res = delete_ssh_key(name)
            self._send(200, res)
            return

        elif p == "/api/backup/upload":
            content = data.get("content", "")
            if not content:
                self._send(200, {"ok": False, "msg": "备份内容为空"}); return
            try:
                raw = base64.b64decode(content)
                obj = json.loads(raw.decode("utf-8"))
            except Exception as e:
                self._send(200, {"ok": False, "msg": "解析备份失败: %s" % e}); return
            ok, msg = _validate_backup(obj)
            if not ok:
                self._send(200, {"ok": False, "msg": msg}); return
            _ensure_backup_dir()
            with open(UPLOAD_BACKUP, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            meta = obj.get("meta", {})
            self._send(200, {"ok": True,
                             "msg": "备份已上传并校验通过, 可点「恢复设置」应用。备份时间: %s" % meta.get("created", "未知"),
                             "created": meta.get("created", "")})
            return

        elif p == "/api/backup/restore":
            if not os.path.exists(UPLOAD_BACKUP):
                self._send(200, {"ok": False, "msg": "没有已上传的备份, 请先上传备份文件"}); return
            try:
                with open(UPLOAD_BACKUP) as f:
                    obj = json.load(f)
            except Exception as e:
                self._send(200, {"ok": False, "msg": "读取上传备份失败: %s" % e}); return
            ok, msg = _apply_backup(obj)
            if not ok:
                self._send(200, {"ok": False, "msg": "恢复失败: " + msg}); return
            self._send(200, {"ok": True, "msg": "设置已恢复并应用: " + msg})
            return

        elif p == "/api/backup/default_save":
            _ensure_backup_dir()
            tpl = _build_template()
            with open(DEFAULT_BACKUP, "w", encoding="utf-8") as f:
                json.dump(tpl, f, ensure_ascii=False, indent=2)
            self._send(200, {"ok": True,
                             "msg": "出厂默认备份已更新 (仅含可移植设置: 路由规则/智能路由/站点标题/页脚, "
                                    "不含任何服务器 IP/端口/密码/密钥/凭据)"})
            return

        elif p == "/api/backup/default_restore":
            if not os.path.exists(DEFAULT_BACKUP):
                self._send(200, {"ok": False, "msg": "出厂默认备份不存在, 请先「保存为出厂默认备份」"}); return
            try:
                with open(DEFAULT_BACKUP) as f:
                    obj = json.load(f)
            except Exception as e:
                self._send(200, {"ok": False, "msg": "读取出厂默认备份失败: %s" % e}); return
            ok, msg = _apply_template(obj)
            if not ok:
                self._send(200, {"ok": False, "msg": "导入失败: " + msg}); return
            self._send(200, {"ok": True,
                             "msg": "已导入出厂默认设置 (已保留本机 IP/端口/密码/密钥/凭据): " + msg})
            return

        elif p == "/api/backup/delete":
            fname = (data.get("file") or "").strip()
            if not fname or ".." in fname or "/" in fname or not fname.endswith(".json"):
                self._send(200, {"ok": False, "msg": "非法文件名"}); return
            _skip = ("default_backup.json", "uploaded_backup.json")
            if fname in _skip:
                self._send(200, {"ok": False, "msg": "不允许删除系统保留文件"}); return
            fp = os.path.join(BACKUP_DIR, fname)
            if not os.path.isfile(fp):
                self._send(200, {"ok": False, "msg": "文件不存在"}); return
            os.remove(fp)
            self._send(200, {"ok": True, "msg": "已删除: " + fname})
            return

        elif p == "/api/ssh_brute_set":
            tgt = data.get("target", "entry")
            enable = bool(data.get("enable", False))
            res = ssh_brute_set(tgt, enable)
            self._send(200, res)
            return

        elif p == "/api/brute_set":
            try:
                window = int(data.get("window", 60))
                maxfail = int(data.get("max", 17))
                ban = int(data.get("ban", 17200))
            except Exception:
                self._send(200, {"ok": False, "msg": "参数格式错误"}); return
            if not (1 <= window <= 3600):
                self._send(200, {"ok": False, "msg": "统计窗口需在 1-3600 秒"}); return
            if not (1 <= maxfail <= 1000):
                self._send(200, {"ok": False, "msg": "失败次数需在 1-1000"}); return
            if not (30 <= ban <= 31536000):
                self._send(200, {"ok": False, "msg": "封锁时长需在 30-31536000 秒"}); return
            save_brute_config(window, maxfail, ban)
            synced = []
            try:
                st2 = load_state()
                for tgt in ["entry"] + [e["tag"] for e in st2.get("exits", [])]:
                    st_brute = ssh_brute_status(tgt)
                    if st_brute.get("installed") and st_brute.get("jail_on"):
                        ssh_brute_set(tgt, True)
                        synced.append(tgt)
            except Exception:
                pass
            self._send(200, {"ok": True,
                             "window": window, "max": maxfail, "ban": ban, "synced": synced,
                             "msg": "已保存防护参数 (窗口 %d 秒 / 失败 %d 次 / 封锁 %d 秒)%s" % (
                                 window, maxfail, ban,
                                 ("；已同步到 SSH fail2ban: " + ",".join(synced)) if synced else "；SSH 防护未启用, 仅面板规则生效")})
            return

        elif p == "/api/machine_backup/start":
            tgt = data.get("target", "entry")
            res = machine_backup_start(tgt)
            self._send(200, res)
            return

        elif p == "/api/machine_backup/delete":
            tgt = data.get("target", "entry")
            fname = (data.get("file") or "").strip()
            res = machine_backup_delete(tgt, fname)
            self._send(200, res)
            return

        elif p == "/api/routing_rules":
            st = load_state()
            body = data if isinstance(data, dict) else {}
            st["smart_routing"] = bool(body.get("enabled", False))
            raw_rules = body.get("rules", [])
            valid_out = {ex["tag"] for ex in st["exits"]} | {"direct", "block"}
            valid_types = {"domain_suffix", "domain_full", "keyword", "ip", "geoip", "port"}
            clean = []
            for i, r in enumerate(raw_rules):
                rt = r.get("type"); rv = (r.get("value") or "").strip(); ob = r.get("outbound")
                if rt not in valid_types or not rv or ob not in valid_out:
                    continue
                clean.append({"id": "r%d" % (i + 1), "type": rt, "value": rv,
                              "outbound": ob, "enabled": bool(r.get("enabled", True))})
            st["routing_rules"] = clean
            # GeoIP 规则依赖 geoip.dat, 缺失/无效时应用会拖崩 xray, 故先拦截
            if any(r["type"] == "geoip" for r in clean):
                if not geoip_is_valid():
                    self._send(200, {"ok": False,
                        "msg": "GeoIP.dat 无效或缺失 (xray 无法加载), 无法应用 GeoIP 规则。"
                               "请先安装有效的 geoip.dat, 或改用 IP/CIDR/域名规则。当前配置未改动。"})
                    return
            save_state(st)
            ok, msg = apply_config(st)
            self._send(200, {"ok": ok, "msg": msg, "rules": clean,
                             "enabled": st["smart_routing"]})
            return

        else:
            self._send(404, {"ok": False, "msg": "not found"})

    def do_DELETE(self):
        if not self._auth():
            self._send(401, {"ok": False, "msg": "未授权"}); return
        p = self._api_path()
        if p is None:
            self._send(404, {"ok": False, "msg": "not found"}); return
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        st = load_state()
        if p == "/api/exit":
            i = int(data["index"])
            if 0 <= i < len(st["exits"]):
                removed = st["exits"].pop(i)
                st["inbounds"] = [b for b in st["inbounds"] if b["exit"] != removed["tag"]]
                save_state(st)
                self._send(200, {"ok": True, "msg": f"已删除出口 {removed['name']} (及其关联入口)"})
            else:
                self._send(200, {"ok": False, "msg": "索引越界"})
        elif p == "/api/inbound":
            i = int(data["index"])
            if 0 <= i < len(st["inbounds"]):
                removed = st["inbounds"].pop(i)
                save_state(st)
                self._send(200, {"ok": True, "msg": f"已删除入口端口 {removed['port']}"})
            else:
                self._send(200, {"ok": False, "msg": "索引越界"})
        else:
            self._send(404, {"ok": False, "msg": "not found"})


def main():
    os.makedirs(BASE, exist_ok=True)
    load_state()
    # 加载整机备份任务状态: 若上次进程遗留 running(服务重启导致中断), 标记为 error 避免永久阻塞
    _load_machine_jobs()
    for _t, _j in list(machine_jobs.items()):
        if _j.get("state") == "running":
            _j["state"] = "error"
            _j["error"] = "上次备份任务因服务重启被中断"
            _j["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _save_machine_jobs()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"x-cfui panel on :{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
