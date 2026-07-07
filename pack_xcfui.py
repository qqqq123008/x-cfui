#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_xcfui.py —— 从「修复后的源码」重新生成 xcfui 备份包(.tar.gz)

设计原则(治本 / 源码唯一真相):
  - 备份包里的面板代码(opt/x-cfui/app.py, opt/x-cfui/_restore_xcfui.sh)必须来自源码目录,
    而不是手工去改包里的字节。改源码 -> 跑本脚本 -> 干净的备份包。
  - 服务器状态(ssh 密钥/证书/xray 配置/state.json/ban.json 等)原样保留, 含 600 权限与硬链接。
  - 这样 BUG 不会随"源码打包"回来: 只要源码修好, 重打包即是干净产物。

用法:
  python3 pack_xcfui.py                      # 读 backups/ 下最新 xcfui_backup_*.tar.gz, 原地重生成(先备份)
  python3 pack_xcfui.py <现有包> [输出包]     # 指定源与输出
"""
import os, sys, tarfile, time, io, glob, shutil

SRC = os.path.dirname(os.path.abspath(__file__))
APP_SRC = os.path.join(SRC, "app.py")
RESTORE_SRC = os.path.join(SRC, "restore_xcfui.sh")
BACKUP_DIR = os.path.join(SRC, "backups")

# 这些成员来自源码(覆盖更新), 不从旧包复制
SOURCE_MEMBERS = {
    "opt/x-cfui/app.py": (APP_SRC, 0o644),
    "opt/x-cfui/_restore_xcfui.sh": (RESTORE_SRC, 0o755),
}


def find_latest_backup():
    pkgs = sorted(glob.glob(os.path.join(BACKUP_DIR, "xcfui_backup_*.tar.gz")),
                  key=os.path.getmtime, reverse=True)
    pkgs = [p for p in pkgs if ".bak" not in os.path.basename(p)]
    return pkgs[0] if pkgs else None


def main():
    src_pkg = sys.argv[1] if len(sys.argv) > 1 else find_latest_backup()
    out_pkg = sys.argv[2] if len(sys.argv) > 2 else src_pkg
    if not src_pkg or not os.path.exists(src_pkg):
        print("错误: 找不到现有备份包"); sys.exit(1)
    if not os.path.exists(APP_SRC) or not os.path.exists(RESTORE_SRC):
        print("错误: 缺少源码 app.py / restore_xcfui.sh"); sys.exit(1)

    # 原地输出时, 先备份当前包
    if out_pkg == src_pkg and os.path.exists(out_pkg):
        bak = out_pkg + ".bak2"
        n = 2
        while os.path.exists(bak):
            n += 1
            bak = out_pkg + f".bak{n}"
        shutil.copy2(out_pkg, bak)
        print(f"已备份当前包 -> {bak}")

    with tarfile.open(src_pkg, "r:gz") as tin, \
         tarfile.open(out_pkg, "w:gz") as tout:
        # 1) 复制旧包所有成员(保留元数据: 权限/uid/gid/mtime/硬链/软链)
        for m in tin.getmembers():
            if m.name in SOURCE_MEMBERS:
                continue  # 这些用源码版本覆盖
            if m.isreg():
                data = tin.extractfile(m).read()
                tout.addfile(m, io.BytesIO(data))
            else:
                tout.addfile(m)
        # 2) 用修复后的源码覆盖面板代码成员
        for name, (path, mode) in SOURCE_MEMBERS.items():
            data = open(path, "rb").read()
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            ti.uid = 0
            ti.gid = 0
            ti.mtime = int(time.time())
            ti.size = len(data)
            tout.addfile(ti, io.BytesIO(data))

    print(f"已重新生成备份包(源码派生): {out_pkg}")
    print(f"  大小: {os.path.getsize(out_pkg)} 字节")
    print(f"  面板代码来自源码: {os.path.basename(APP_SRC)} / {os.path.basename(RESTORE_SRC)}")
    print(f"  服务器状态(密钥/证书/配置)原样保留。")


if __name__ == "__main__":
    main()
