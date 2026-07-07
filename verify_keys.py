#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 SSH 密钥库: 上传 / 列出 / 删除。"""
import paramiko, base64, json

KEY = "ssh_keys_backup/cn_id_ed25519.pem"
CN = {"host": "47.108.200.193", "port": 22022, "user": "root"}
TOKEN = "aa888888"

TEST_PEM = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAIF3J2k5Z
ZmFrZS1mb3ItdGVzdC1vbmx5AAAAA3Rlc3QAAAAdzc2gtZWQyNTUxOQAAAAAAAAAB
AAAAA3Rlc3QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END OPENSSH PRIVATE KEY-----
"""
b64 = base64.b64encode(TEST_PEM.encode()).decode()

def run():
    key = paramiko.Ed25519Key.from_private_key_file(KEY)
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CN["host"], port=CN["port"], username=CN["user"], pkey=key, timeout=25, look_for_keys=False, allow_agent=False)
    def curl(method, path, data=None):
        if data is None:
            cmd = f"curl -s -m 20 -u {TOKEN}:{TOKEN} 'http://127.0.0.1:5000/aa888888{path}'"
        else:
            j = json.dumps(data).replace("'", "'\\''")
            cmd = f"curl -s -m 20 -u {TOKEN}:{TOKEN} -H 'Content-Type: application/json' -X {method} -d '{j}' 'http://127.0.0.1:5000/aa888888{path}'"
        _, o, e = c.exec_command(cmd, timeout=40)
        return o.read().decode(errors="replace").strip()
    print("1) 上传前列表:", curl("GET", "/api/ssh_keys"))
    print("2) 上传 test_key.pem:", curl("POST", "/api/ssh_key_upload", {"name": "test_key.pem", "content": b64}))
    print("3) 上传后列表:", curl("GET", "/api/ssh_keys"))
    print("4) 删除 test_key.pem:", curl("POST", "/api/ssh_key_delete", {"name": "test_key.pem"}))
    print("5) 删除后列表:", curl("GET", "/api/ssh_keys"))
    # 防路径穿越测试
    print("6) 路径穿越尝试 (../../etc/passwd):", curl("POST", "/api/ssh_key_upload", {"name": "../../etc/passwd", "content": b64}))
    c.close()

if __name__ == "__main__":
    run()
