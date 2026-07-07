#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_xcfui.py —— 生成两个自包含单文件:
  xcfui-deploy.sh  — 全新部署(内置 app.py + deploy 脚本), 随机安全信息, 自启即用
  xcfui-restore.sh — 恢复/搬家(内置 backup + restore 脚本), 用已有备份包恢复到新服务器

用法:
    python3 make_xcfui.py

生成后, 用户只需携带对应文件:
    sudo bash xcfui-deploy.sh             # 全新部署一台中继
    sudo bash xcfui-restore.sh            # 用本地备份包在新服务器恢复(默认找 /root 下最新包)
    sudo bash xcfui-restore.sh /path/包.tar.gz  # 指定包恢复

说明:
  - 改完 app.py 后, 在服务器上 `sudo bash xcfui-deploy.sh bake` 即可让部署文件内置最新面板。
  - 恢复文件不内置 app.py(恢复时 app.py 来自备份包本身), 因此无需 bake。
  - make_xcfui.py 是 AI 内部构建工具, 用户日常不需要运行它。
"""
import base64, os, hashlib

SRC = os.path.dirname(os.path.abspath(__file__))
OUT_DEPLOY  = os.path.join(SRC, "xcfui-deploy.sh")
OUT_RESTORE = os.path.join(SRC, "xcfui-restore.sh")

PARTS = {
    "APP":     ("__APP_START__",     "__APP_END__",     os.path.join(SRC, "app.py")),
    "DEPLOY":  ("__DEPLOY_START__",  "__DEPLOY_END__",  os.path.join(SRC, "deploy_xcfui.sh")),
    "BACKUP":  ("__BACKUP_START__",  "__BACKUP_END__",  os.path.join(SRC, "backup_xcfui.sh")),
    "RESTORE": ("__RESTORE_START__", "__RESTORE_END__", os.path.join(SRC, "restore_xcfui.sh")),
}

def b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")

def common_top():
    return r'''#!/usr/bin/env bash
# 强制用真正的 bash 重新执行本脚本(兼容被 /bin/sh(dash) 调用)
REALBASH=""
for _b in bash /usr/bin/bash /bin/bash; do
  if command -v "$_b" >/dev/null 2>&1 && "$_b" -c '[[ -n "$BASH_VERSION" ]]' >/dev/null 2>&1; then REALBASH="$_b"; break; fi
done
if [ -z "${BASH_VERSION:-}" ] && [ -n "$REALBASH" ]; then exec "$REALBASH" "$0" "$@"; fi
set -euo pipefail
# 记录"本包装脚本自身所在目录", 传给内层解压出的脚本, 使其能搜索用户实际放置备份包的目录
WRAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export WRAP_DIR
WORK="$(mktemp -d)"
cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT
extract(){ # $1 起始标记 $2 结束标记 $3 输出文件
  awk -v s="$1" -v e="$2" 'BEGIN{p=0} $0==s{p=1;next} $0==e{p=0} p{print}' "$0" | base64 -d > "$3"
}
'''

def embed(keys):
    blocks = []
    for k in keys:
        start, end, path = PARTS[k]
        with open(path, "rb") as f:
            raw = f.read()
        sha = hashlib.sha256(raw).hexdigest()[:16]
        blocks.append(f"# {k} ({os.path.basename(path)}) sha256:{sha}")
        blocks.append(start)
        blocks.append(b64(path))
        blocks.append(end)
    return "\n".join(blocks) + "\n"

# ---------------- 部署文件 ----------------
deploy_header = common_top() + r'''# ============================================================
# x-cfui 一键部署 (全新中继服务器) — 只需本文件
# ------------------------------------------------------------
#   sudo bash xcfui-deploy.sh             # 全新部署(内置 app.py, 随机安全入口/账户/密码)
#   sudo bash xcfui-deploy.sh bake [路径]  # 用最新 app.py 更新本文件内置面板(默认读本机 /opt/x-cfui/app.py)
# 典型场景: 拿到一台新 Debian 12 中继服务器, 传本文件上去, 一条命令部署完成即可用。
# ============================================================
self_bake(){ # $1 源 app.py 路径(默认读本机运行中面板)
  local src="${1:-/opt/x-cfui/app.py}"
  if [[ ! -f "$src" ]]; then
    echo "错误: 找不到源 app.py: $src"; echo "用法: sudo bash xcfui-deploy.sh bake /path/to/app.py"; exit 1
  fi
  local self="$0"
  base64 -w0 "$src" > "$WORK/app.b64"
  awk -v b64file="$WORK/app.b64" '
    BEGIN{p=0; getline b64 < b64file; close(b64file)}
    $0=="__APP_START__"{print; print b64; p=1; next}
    $0=="__APP_END__"{p=0; print; next}
    p{next}
    {print}
  ' "$self" > "$self.baktmp"
  mv "$self.baktmp" "$self"; chmod +x "$self"
  echo "已更新内置 app.py <- $src"
}
MODE="${1:-deploy}"
case "$MODE" in
  deploy)
    extract __APP_START__ __APP_END__ "$WORK/app.py"
    extract __DEPLOY_START__ __DEPLOY_END__ "$WORK/deploy_xcfui.sh"
    chmod +x "$WORK/deploy_xcfui.sh"
    bash "$WORK/deploy_xcfui.sh"
    ;;
  bake)
    self_bake "${2:-/opt/x-cfui/app.py}"
    ;;
  help|-h|--help|"")
    cat <<'EOF'
x-cfui 一键部署 (只需本文件 xcfui-deploy.sh)
用法:
  sudo bash xcfui-deploy.sh             全新部署(内置 app.py, 随机安全信息, 自启即用)
  sudo bash xcfui-deploy.sh bake [路径] 用最新 app.py 更新本文件内置面板
EOF
    ;;
  *)
    echo "未知动作: $MODE"; echo "用法: sudo bash xcfui-deploy.sh [deploy|bake]"; exit 1
    ;;
esac
exit 0
# ===================== 内嵌文件 (base64) =====================
'''

# ---------------- 恢复/搬家文件 ----------------
restore_header = common_top() + r'''# ============================================================
# x-cfui 一键恢复 / 搬家 (用已有备份包恢复到新服务器) — 只需本文件
# ------------------------------------------------------------
#   sudo bash xcfui-restore.sh                  # 恢复(自动找 /root 下最新 xcfui_backup_*.tar.gz)
#   sudo bash xcfui-restore.sh /path/包.tar.gz   # 指定备份包恢复
#   sudo bash xcfui-restore.sh backup           # (可选)在当前机器做备份
#   sudo bash xcfui-restore.sh migrate <目标IP> [端口] [用户] [--key=密钥] # (可选)两台都在时一键迁移
# 典型搬家场景: 旧服务器已到期, 你本地留有之前的备份包 -> 把包和本文件传到新服务器 ->
#               sudo bash xcfui-restore.sh  即可一键恢复, 恢复后直接可用(入口/密码与原机相同)。
# ============================================================
self_migrate(){
  local dst_ip="${1:-}"; local dst_port="${2:-22}"; local dst_user="${3:-root}"; local keyfile=""
  local a
  for a in "$@"; do case "$a" in --key=*) keyfile="${a#--key=}";; esac; done
  if [[ -z "$dst_ip" ]]; then
    echo "用法: sudo bash xcfui-restore.sh migrate <目标IP> [端口] [用户] [--key=密钥路径]"; exit 1
  fi
  echo "==> [1/3] 备份当前机器 ..."
  extract __BACKUP_START__ __BACKUP_END__ "$WORK/backup_xcfui.sh"
  chmod +x "$WORK/backup_xcfui.sh"
  bash "$WORK/backup_xcfui.sh"
  local pkg; pkg="$(ls -t /root/xcfui_backup_*.tar.gz 2>/dev/null | head -1)"
  [[ -f "$pkg" ]] || { echo "错误: 备份未生成"; exit 1; }
  echo "    备份包: $pkg"
  local self="$0"
  local ssh_base="-p $dst_port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
  local scp_base="-P $dst_port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
  if [[ -n "$keyfile" ]]; then
    ssh_base="-i $keyfile $ssh_base"; scp_base="-i $keyfile $scp_base"
  else
    command -v sshpass >/dev/null 2>&1 || { echo "错误: 无 --key 且系统无 sshpass"; exit 1; }
    read -rs -p "请输入目标机 $dst_user@$dst_ip 的密码: " DST_PASS < /dev/tty; echo
    export SSHPASS="$DST_PASS"; ssh_base="sshpass -e $ssh_base"; scp_base="sshpass -e $scp_base"
  fi
  echo "==> [2/3] 传输到 $dst_user@$dst_ip ..."
  scp $scp_base "$pkg" "$self" "$dst_user@$dst_ip:/root/" || { echo "错误: 传输失败"; exit 1; }
  echo "==> [3/3] 在目标机执行恢复 ..."
  ssh $ssh_base "$dst_user@$dst_ip" "bash /root/xcfui-restore.sh restore" || { echo "错误: 恢复失败"; exit 1; }
  echo "==> 迁移完成! 访问: http://$dst_ip:5000/<入口密令与原机相同>"
}
# 兼容直接给备份包路径(不带 restore 动词): sudo bash xcfui-restore.sh /path/包.tar.gz
case "${1:-}" in
  restore|list|backup|migrate|help|-h|--help|"") ;;
  *) set -- restore "$1" ;;
esac
MODE="${1:-restore}"
case "$MODE" in
  restore)
    extract __RESTORE_START__ __RESTORE_END__ "$WORK/restore_xcfui.sh"
    chmod +x "$WORK/restore_xcfui.sh"
    bash "$WORK/restore_xcfui.sh" "${2:-}"
    ;;
  list)
    extract __RESTORE_START__ __RESTORE_END__ "$WORK/restore_xcfui.sh"
    chmod +x "$WORK/restore_xcfui.sh"
    bash "$WORK/restore_xcfui.sh" list
    ;;
  backup)
    extract __BACKUP_START__ __BACKUP_END__ "$WORK/backup_xcfui.sh"
    extract __RESTORE_START__ __RESTORE_END__ "$WORK/restore_xcfui.sh"
    chmod +x "$WORK/backup_xcfui.sh"
    bash "$WORK/backup_xcfui.sh" "${@:2}"
    ;;
  migrate)
    self_migrate "${@:2}"
    ;;
  help|-h|--help)
    cat <<'EOF'
x-cfui 一键恢复 / 搬家 (只需本文件 xcfui-restore.sh)
用法:
  sudo bash xcfui-restore.sh                  恢复(自动找 /root 下最新备份包)
  sudo bash xcfui-restore.sh /path/包.tar.gz   指定包恢复
  sudo bash xcfui-restore.sh list             列出当前可用的备份包(含名称/大小)
  sudo bash xcfui-restore.sh backup           在当前机器做备份
  sudo bash xcfui-restore.sh migrate <IP> ..   两台都在时一键迁移
EOF
    ;;
  *)
    echo "未知动作: $MODE"; echo "用法: sudo bash xcfui-restore.sh [restore|backup|migrate]"; exit 1
    ;;
esac
exit 0
# ===================== 内嵌文件 (base64) =====================
'''

with open(OUT_DEPLOY, "w", encoding="utf-8", newline="\n") as f:
    f.write(deploy_header)
    f.write(embed(["APP", "DEPLOY"]))
with open(OUT_RESTORE, "w", encoding="utf-8", newline="\n") as f:
    f.write(restore_header)
    f.write(embed(["BACKUP", "RESTORE"]))

print("已生成:")
print(" ", OUT_DEPLOY, os.path.getsize(OUT_DEPLOY), "字节")
print(" ", OUT_RESTORE, os.path.getsize(OUT_RESTORE), "字节")
