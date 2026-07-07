#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断三台服务器真实 ufw 状态(用全新连接, 排除 enable 杀死会话导致的误报)。
CN 用本地 cn 密钥; SG/RU 经 CN 上的面板管理密钥 /root/.ssh/xcfui_ed25519 跳转。"""
import paramiko

CN_HOST, CN_PORT, CN_KEY = "47.108.200.193", 22022, "ssh_keys_backup/cn_id_ed25519.pem"
PANEL_KEY = "/root/.ssh/xcfui_ed25519"  # 存在于 CN 上, 已预置 SG/RU authorized_keys


def cn_connect():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN_HOST, port=CN_PORT, username="root",
              pkey=paramiko.Ed25519Key.from_private_key_file(CN_KEY), timeout=20)
    return c


def run(c, cmd, timeout=60):
    _, o, e = c.exec_command(cmd, timeout=timeout)
    return o.read().decode(errors="replace").strip(), e.read().decode(errors="replace").strip()


def main():
    c = cn_connect()
    print("=== CN ufw ===")
    out, _ = run(c, "ufw status verbose; echo '---'; systemctl is-active ufw 2>/dev/null; echo '---RULES---'; ufw status numbered")
    print(out)

    for name, host, port in [("SG", "43.156.107.54", 23022), ("RU", "193.53.126.80", 24022)]:
        print(f"\n=== {name} ufw (via CN jump, panel key) ===")
        cmd = (f"ssh -i {PANEL_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=15 "
               f"-p {port} root@{host} 'ufw status verbose; echo ---; systemctl is-active ufw; "
               f"echo ---RULES---; ufw status numbered'")
        out, err = run(c, cmd, timeout=40)
        print(out or err)
    c.close()


if __name__ == "__main__":
    main()
