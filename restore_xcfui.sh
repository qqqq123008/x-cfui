#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# restore_xcfui.sh —— x-cfui 一键恢复脚本(在新 Debian 12 机器上还原完整面板)
#
# 用途:
#   把 backup_xcfui.sh 生成的备份包, 在原样还原到一台新机器上,
#   "无需任何二次操作或命令"即可直接使用(面板/账号/入口/节点/分流/加密/伪装/UUID/BBR/防火墙 全部就位)。
#
# 用法:
#   sudo bash restore_xcfui.sh                         # 自动找最新的 xcfui_backup_*.tar.gz
#   sudo bash restore_xcfui.sh /path/to/xxx.tar.gz     # 指定包
#   sudo bash restore_xcfui.sh /path/to/xxx.tar.gz.enc # 自动读取同名 .key 解密
#
# 行为:
#   1) 安装基础依赖 + Xray(若新机缺失)
#   2) 解密(.enc 自动读同名 .key)
#   3) 停旧服务 -> 还原所有文件到绝对路径 -> 重新 home CN 地址到本机 -> 应用 BBR
#   4) 依次重启 ssh / xray / fail2ban / nginx / 面板
#   5) 按备份中的端口配置 ufw 防火墙
#
# 注意: 本脚本会覆盖目标机器上同路径的文件, 仅应在" intended 的新机器"上运行。
#
set -euo pipefail

# 无论你在哪个目录执行本脚本, 都会搜索"脚本所在目录", 所以把备份包和本脚本放一起即可
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "[错误] 请使用 root 运行: sudo bash $0" >&2
  exit 1
fi

# ===================== 列出可用备份包(list 动作) =====================
if [[ "${1:-}" == "list" ]]; then
  echo "可用备份包(搜索: 脚本所在目录 / 当前目录 / /root):"
  found=0
  for f in "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_backup_*.tar.gz "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_backup_*.tar.gz.enc \
           "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_migration_*.tar.gz \
           ./xcfui_backup_*.tar.gz ./xcfui_backup_*.tar.gz.enc \
           ./xcfui_migration_*.tar.gz \
           /root/xcfui_backup_*.tar.gz /root/xcfui_backup_*.tar.gz.enc \
           /root/xcfui_migration_*.tar.gz; do
    [[ -e "$f" ]] || continue
    found=1
    printf "  %s  (%s)\n" "$f" "$(du -h "$f" 2>/dev/null | cut -f1)"
  done
  [[ $found -eq 0 ]] && echo "  (未找到。备份包命名形如: xcfui_backup_<主机名>_<时间>.tar.gz)"
  echo
  echo "恢复用法:"
  echo "  sudo bash xcfui-restore.sh                  # 自动选用最新包"
  echo "  sudo bash xcfui-restore.sh /路径/包.tar.gz   # 指定包"
  echo "说明: 备份包在源服务器的 /root/ 下生成(由 backup 动作产生)。"
  echo "      搬家时把『本脚本 xcfui-restore.sh』和『备份包 .tar.gz』一起传到新服务器同一目录即可,"
  echo "      任意目录都行(脚本会自动找自己旁边的包), 然后在该目录执行 sudo bash xcfui-restore.sh。"
  exit 0
fi

log(){ echo -e "\033[1;36m[恢复]\033[0m $*"; }
ok(){ echo -e "\033[1;32m[OK]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[警告]\033[0m $*"; }

# ===================== 定位备份包 =====================
if [[ -n "${1:-}" ]]; then
  ARCHIVE="$1"
else
  ARCHIVE="$(ls -t "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_backup_*.tar.gz "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_backup_*.tar.gz.enc \
                  "${WRAP_DIR:-$SCRIPT_DIR}"/xcfui_migration_*.tar.gz \
                  ./xcfui_backup_*.tar.gz ./xcfui_backup_*.tar.gz.enc \
                  ./xcfui_migration_*.tar.gz \
                  /root/xcfui_backup_*.tar.gz /root/xcfui_backup_*.tar.gz.enc \
                  /root/xcfui_migration_*.tar.gz 2>/dev/null | head -1)"
fi
if [[ -z "${ARCHIVE:-}" || ! -f "$ARCHIVE" ]]; then
  echo "[错误] 未找到备份包。" >&2
  echo "        请把备份包(xcfui_backup_*.tar.gz 或 .enc)和本脚本放在同一目录," >&2
  echo "        或放到 /root/ 下, 或显式指定路径: sudo bash xcfui-restore.sh /路径/包.tar.gz" >&2
  echo "        备份包命名形如: xcfui_backup_<主机名>_<时间>.tar.gz" >&2
  echo "        当前脚本所在目录: $SCRIPT_DIR" >&2
  exit 1
fi
log "使用备份包: $ARCHIVE"

# ===================== 解密(若为 .enc) =====================
DECARCH="$ARCHIVE"
if [[ "$ARCHIVE" == *.enc ]]; then
  KEYFILE="${ARCHIVE%.enc}.key"
  if [[ ! -f "$KEYFILE" ]]; then
    echo "[错误] 未找到密钥文件: $KEYFILE (加密包需同名 .key 一起提供)" >&2
    exit 1
  fi
  DECARCH="$(mktemp --suffix=.tar.gz)"
  log "解密备份包..."
  openssl enc -aes-256-cbc -pbkdf2 -d -in "$ARCHIVE" -out "$DECARCH" -pass "file:$KEYFILE" >/dev/null 2>&1
  ok "解密完成"
fi

# ===================== 解包到临时目录 =====================
TMP="$(mktemp -d)"
tar -xzf "$DECARCH" -C "$TMP"
ok "备份包已解压到临时目录"

# 探测备份中的关键信息(用于重新 home / 防火墙)
OLD_CN_IP="$(grep -oE 'CN_ADDR = "[0-9.]+"' "$TMP/opt/x-cfui/app.py" 2>/dev/null | grep -oE '[0-9.]+' | head -1 || true)"
ENTRY_TOKEN=""
ADMIN_USER=""
# 直接从解包后的 state.json 读入口密令与管理员账户(更可靠)
if [[ -f "$TMP/opt/x-cfui/state.json" ]]; then
  ENTRY_TOKEN="$(python3 -c "import json;print(json.load(open('$TMP/opt/x-cfui/state.json')).get('entry_token',''))" 2>/dev/null || true)"
  ADMIN_USER="$(python3 -c "import json;print(json.load(open('$TMP/opt/x-cfui/state.json')).get('admin_user',''))" 2>/dev/null || true)"
fi

# ===================== 基础依赖检查(离线模式: 不联网下载) =====================
log "检查基础依赖(所有必需文件应在备份包内)..."
for cmd in python3 nginx ufw fail2ban qrencode; do
  command -v $cmd >/dev/null 2>&1 || warn "缺少命令: $cmd (请在新机先 apt install)"
done

# 安装面板 Python 依赖(segno) — 从备份包 .bundle/segno 离线安装
log "安装面板 Python 依赖(segno)..."
if python3 -c "import segno" 2>/dev/null; then
  ok "segno 已安装"
else
  SEGNO_SRC="/opt/x-cfui/.bundle/segno"
  if [[ -d "$SEGNO_SRC" ]]; then
    PYTHON_SITE="$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)"
    if [[ -n "$PYTHON_SITE" ]]; then
      cp -r "$SEGNO_SRC" "$PYTHON_SITE/segno"
      ok "segno 已从本地包离线安装"
    fi
  else
    warn "备份包内无 segno 离线包, 二维码生成不可用"
  fi
fi

# xray 二进制已随备份包还原(/usr/local/bin/xray), 仅检查
if [[ ! -x /usr/local/bin/xray ]]; then
  warn "/usr/local/bin/xray 不存在(备份包应含 xray 二进制), 请确认备份包版本"
fi

# ===================== 停旧服务(不碰 ssh) =====================
log "停止相关服务(保留 SSH)..."
for s in x-cfui xray fail2ban nginx; do
  systemctl stop "$s" 2>/dev/null || true
done

# ===================== 还原文件到绝对路径 =====================
log "还原所有 x-cfui 文件到系统绝对路径..."
tar -C "$TMP" --numeric-owner -cf - . | tar -C / --numeric-owner -xpf -
ok "文件还原完成"

# 清理临时解包目录
rm -rf "$TMP"

# 删除备份包内自带的 _restore_xcfui.sh 旧副本:
# 旧版该脚本的 re-home 用 hostname -I(内网 IP, 如 172.x), 会导致客户端连不上;
# 真正的恢复由本脚本(xcfui-restore.sh)完成, 且已用公网 IP 正确 re-home,
# 残留的旧副本仅会误导误用, 故恢复后直接移除(权威恢复工具就是本脚本本身)。
rm -f /opt/x-cfui/_restore_xcfui.sh

# ===================== 重新 home: 把 CN 地址指向本机 =====================
NEW_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
# 获取公网 IP: 优先命令行第二参数(手动指定), 否则自动获取(有外网)
if [[ -n "${2:-}" ]]; then
  PUB_IP="$2"
else
  PUB_IP="$(curl -fsSL -m 5 ifconfig.me 2>/dev/null || echo '')"
fi
if [[ -z "$PUB_IP" ]]; then
  warn "无法获取公网 IP, 将使用内网 IP: $NEW_IP"
  warn "若客户端无法连接, 请重跑: sudo bash $0 备份包.tar.gz 新机公网IP"
fi
# 重新 home 必须用公网 IP: 云厂商 VPS 的 hostname -I 第一字段是内网 IP(如 172.x), 客户端无法连接
REHOME_IP="${PUB_IP:-$NEW_IP}"
if [[ -n "$OLD_CN_IP" && -n "$REHOME_IP" && "$OLD_CN_IP" != "$REHOME_IP" && -f /opt/x-cfui/app.py ]]; then
  log "重新定位 CN 地址: $OLD_CN_IP -> $REHOME_IP (让新机器成为面板控制节点)"
  sed -i "s/$OLD_CN_IP/$REHOME_IP/g" /opt/x-cfui/app.py
  ok "CN 地址已重新定位到本机(目标 IP: $REHOME_IP)"
elif [[ -n "$OLD_CN_IP" && -z "$REHOME_IP" ]]; then
  warn "未获取到任何本机 IP, 已跳过 CN 地址重新定位; 面板仍指向旧 IP $OLD_CN_IP, 请在面板手动修正。"
fi

# 更新 cn_ssh_port 为新机 sshd 实际端口(默认 22)
SSHD_PORT="$(grep -hE '^\s*Port\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | tail -1)"
SSHD_PORT="${SSHD_PORT:-22}"
if [[ -f /opt/x-cfui/state.json ]]; then
  python3 - <<PY
import json
p="/opt/x-cfui/state.json"
try:
    d=json.load(open(p))
    d["cn_ssh_port"]=${SSHD_PORT}
    # 治本: 把 CN 地址写入 state.json 的 cn_addr 字段(面板现从 state.json 读地址, 无需依赖 sed 改写源码)
    d["cn_addr"]="${REHOME_IP}"
    json.dump(d,open(p,"w"),indent=2,ensure_ascii=False)
except Exception as e:
    print("更新 cn_ssh_port 失败(可稍后在面板修改):", e)
PY
fi

# ===================== 应用 BBR / sysctl =====================
log "应用 sysctl(BBR 等)..."
sysctl --system >/dev/null 2>&1 || true
modprobe tcp_bbr 2>/dev/null || true

# ===================== 同步服务状态(完全按旧机: enable/disable + start/stop) =====================
log "重载 systemd 并同步服务状态(与旧机完全一致)..."
systemctl daemon-reload

# 先确保 SSH 可连
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
ok "SSH 已重启(主机密钥已还原)"

# 从备份包读取服务状态并精确同步
if [[ -f /opt/x-cfui/.service_states.json ]]; then
  python3 - <<'PY'
import json, subprocess, sys
with open('/opt/x-cfui/.service_states.json') as f:
    states = json.load(f)
for svc, s in states.items():
    if svc == "ssh":
        continue  # SSH 已单独处理, 避免断连
    en = s.get("enabled", "enabled")
    act = s.get("active", "active")
    # 同步 enable/disable/mask
    if en in ("enabled", "disabled", "masked"):
        subprocess.run(["systemctl", en, svc], capture_output=True)
    # 同步 start/stop
    subprocess.run(["systemctl", "start" if act == "active" else "stop", svc], capture_output=True)
    print(f"  {svc}: {en}+{act}")
PY
  ok "服务状态已同步"
else
  # 兼容旧包: 无 .service_states.json 时仍尝试启动核心服务
  warn "备份包无服务状态记录, 按默认尝试启动..."
  for s in xray fail2ban nginx x-cfui; do
    systemctl enable "$s" 2>/dev/null || true
    systemctl restart "$s" 2>/dev/null || true
  done
fi

# 防火墙规则已通过 ufw 配置文件还原, 不再单独 enable ufw(由上方状态同步控制)

# ufw 规则已通过文件还原, 状态由 .service_states.json 同步控制
# 确保 SSH 连接端口在 ufw 规则中放行(防止下次 enable 时锁死)
if [[ -f /opt/x-cfui/.service_states.json ]]; then
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    cport="$(echo "$SSH_CONNECTION" | awk '{print $4}')"
    ufw allow "${cport}/tcp" >/dev/null 2>&1 || true
  fi
fi
ok "防火墙规则文件已还原"

# ===================== 自检 + 完成 =====================
PANEL_ACTIVE="$(systemctl is-active x-cfui 2>/dev/null || echo inactive)"
XRAY_ACTIVE="$(systemctl is-active xray 2>/dev/null || echo inactive)"

echo
echo -e "\033[1;32m================ 恢复完成 ================\033[0m"
echo -e " 安全入口(浏览器打开): \033[1;33mhttp://${REHOME_IP}:5000/${ENTRY_TOKEN}\033[0m"
if [[ -n "$ADMIN_USER" ]]; then
  echo -e " 管理员账户: \033[1;33m${ADMIN_USER}\033[0m (密码与备份中一致)"
fi
echo " 面板服务: $PANEL_ACTIVE | Xray: $XRAY_ACTIVE"
echo -e "\033[1;32m==========================================\033[0m"
if [[ "$PANEL_ACTIVE" != "active" || "$XRAY_ACTIVE" != "active" ]]; then
  warn "有服务未处于 active, 请检查: journalctl -u x-cfui / journalctl -u xray"
else
  ok "所有服务已启动, 直接打开上面的安全入口即可使用(账号/入口/节点/分流/加密/伪装/UUID/BBR/防火墙 已全部还原)。"
fi
