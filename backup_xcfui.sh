#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# backup_xcfui.sh —— x-cfui 一键备份脚本(仅备份 x-cfui 相关数据, 不含 Debian 系统)
#
# 备份范围(全部 x-cfui 相关设置, 满足"所有数据"诉求):
#   面板设置(state.json) / 面板程序(app.py) / 登录封禁(ban.json) / 暴力破解配置(brute_config.json)
#   连接用密钥库(ssh_keys) / 服务器登录私钥(host_keys) / 面板备份目录(backups)
#   Xray 分流与证书(/usr/local/etc/xray)  —— 含 加密/伪装/UUID/节点/分流 全部配置
#   SSH 身份与主机密钥(/etc/ssh, /root/.ssh)  —— 含 端口与 SSH 密钥
#   fail2ban 配置 / sysctl(BBR) / nginx 网站(/etc/nginx,/var/www/html)
#   systemd 单元(xray.service, x-cfui.service) / nftables 配置
#   活动防火墙规则导出 + MANIFEST 清单(一并打进包内)
#
# 用法:
#   sudo bash backup_xcfui.sh                 # 生成未加密备份(直接可用于一键恢复)
#   sudo bash backup_xcfui.sh --encrypt       # 额外生成 .enc 加密包 + .key 密钥文件
#
# 输出:
#   /root/xcfui_backup_<主机名>_<时间>.tar.gz            (未加密)
#   /root/xcfui_backup_<主机名>_<时间>.tar.gz.enc + .key  (仅 --encrypt 时)
# 包内自带 restore_xcfui.sh(自包含), 复制到新机器后执行即可一键恢复。
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[错误] 请使用 root 运行: sudo bash $0" >&2
  exit 1
fi

ENCRYPT=0
for a in "$@"; do
  case "$a" in
    --encrypt) ENCRYPT=1 ;;
  esac
done

PANEL_DIR="/opt/x-cfui"
META="$PANEL_DIR/.backup_meta"
HOST="$(hostname)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="/root"
ARCHIVE="$OUT_DIR/xcfui_backup_${HOST}_${TS}.tar.gz"

log(){ echo -e "\033[1;36m[备份]\033[0m $*"; }
ok(){ echo -e "\033[1;32m[OK]\033[0m $*"; }

# ===================== 准备元信息(防火墙导出 + 清单) =====================
log "准备备份元信息..."
mkdir -p "$META"
iptables-save > "$META/firewall_iptables.save" 2>/dev/null || true
nft list ruleset > "$META/firewall_nft.save" 2>/dev/null || true
{
  echo "x-cfui 应用与配置完整备份 (不含 Debian 系统文件)"
  echo "生成时间: $(date)"
  echo "主机名: $(hostname)"
  echo "包含: 面板设置(state.json)/面板程序(app.py)/登录封禁/暴力破解配置/连接密钥库/服务器私钥/"
  echo "      Xray 分流与证书(加密/伪装/UUID/节点/客户端)/SSH 身份与主机密钥/SSH 端口/"
  echo "      fail2ban/BBR(sysctl)/nginx 网站/系统服务(xray,x-cfui)/nftables"
} > "$META/MANIFEST.txt"

# 把 restore 脚本塞进包内, 实现自包含一键恢复
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/restore_xcfui.sh" ]]; then
  cp "$SCRIPT_DIR/restore_xcfui.sh" "$PANEL_DIR/_restore_xcfui.sh"
fi

# ===================== 组装要备份的路径清单(仅存在的) =====================
LIST="$(mktemp)"
EXCL="$(mktemp)"
# 排除: 本次产生的备份包自身, 以及历史整机备份(避免无限膨胀/递归)
echo "$ARCHIVE" > "$EXCL"
echo "$OUT_DIR/xcfui_backup_*.tar.gz" >> "$EXCL"
echo "$OUT_DIR/xcfui_backup_*.tar.gz.enc" >> "$EXCL"
echo "$OUT_DIR/xcfui_backup_*.tar.gz.key" >> "$EXCL"
echo "$PANEL_DIR/machine_backups" >> "$EXCL"

for p in \
  /opt/x-cfui/state.json \
  /opt/x-cfui/app.py \
  /opt/x-cfui/ban.json \
  /opt/x-cfui/brute_config.json \
  /opt/x-cfui/ssh_keys \
  /opt/x-cfui/host_keys \
  /opt/x-cfui/backups \
  /opt/x-cfui/_restore_xcfui.sh \
  /opt/x-cfui/.backup_meta \
  /usr/local/etc/xray \
  /etc/ssh \
  /root/.ssh \
  /etc/fail2ban \
  /etc/sysctl.d \
  /etc/systemd/system/xray.service \
  /etc/systemd/system/x-cfui.service \
  /etc/nginx \
  /var/www/html \
  /etc/nftables.conf ; do
  if [[ -e "$p" ]]; then
    echo "$p" >> "$LIST"
  fi
done

if [[ ! -s "$LIST" ]]; then
  echo "[错误] 未找到任何可备份的 x-cfui 文件, 请确认 /opt/x-cfui 存在。" >&2
  rm -f "$LIST" "$EXCL"
  exit 1
fi

# ===================== 打包 =====================
log "正在打包(仅应用与配置, 不含系统文件)..."
tar --numeric-owner -czpf "$ARCHIVE" -X "$EXCL" -T "$LIST" >/dev/null 2>&1
RC=$?
rm -f "$LIST" "$EXCL" "$PANEL_DIR/_restore_xcfui.sh"
if [[ "$RC" -ne 0 && "$RC" -ne 1 ]]; then
  echo "[错误] tar 打包失败 (rc=$RC)" >&2
  rm -f "$ARCHIVE"
  exit 1
fi

SIZE="$(du -h "$ARCHIVE" | cut -f1)"
ok "备份完成: $ARCHIVE ($SIZE)"

# ===================== 可选加密 =====================
if [[ "$ENCRYPT" -eq 1 ]]; then
  KEYFILE="${ARCHIVE}.key"
  ENC="${ARCHIVE}.enc"
  # 随机 32 字节密钥, 以十六进制保存
  KEY="$(tr -dc 'a-f0-9' < /dev/urandom | head -c 64)"
  echo -n "$KEY" > "$KEYFILE"
  chmod 600 "$KEYFILE"
  openssl enc -aes-256-cbc -pbkdf2 -salt \
    -in "$ARCHIVE" -out "$ENC" -pass "file:$KEYFILE" >/dev/null 2>&1
  rm -f "$ARCHIVE"
  ESIZE="$(du -h "$ENC" | cut -f1)"
  ok "已加密: $ENC ($ESIZE)  密钥: $KEYFILE"
  echo
  echo -e "\033[1;33m恢复时把 .enc 和 .key 两个文件一起放到新机器, 执行: sudo bash restore_xcfui.sh\033[0m"
  echo -e "\033[1;33m密钥(防 .key 丢失): $KEY\033[0m"
else
  echo
  echo -e "\033[1;33m恢复时把 .tar.gz 放到新机器, 执行: sudo bash restore_xcfui.sh\033[0m"
fi
echo -e "\033[1;32m备份包内已自带 restore_xcfui.sh, 也可解包后直接运行。\033[0m"
