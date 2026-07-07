#!/usr/bin/env python3
# 在 SG 出口服务器下载 v2fly 官方 legacy geoip.dat (SG 有正常外网), 校验后传回 CN
import paramiko

CN = "47.108.200.193"; CN_PORT = 22022; CN_KEY = "ssh_keys_backup/cn_id_ed25519.pem"
SG = "43.156.107.54";  SG_PORT = 23022; SG_KEY = "ssh_keys_backup/sg_id_ed25519.pem"
RU = "193.53.126.80";  RU_PORT = 24022; RU_KEY = "ssh_keys_backup/ru_id_ed25519.pem"

URLS = [
    "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
    "https://ghproxy.com/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
    "https://ghproxy.net/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
]

def conn(host, port, key):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username="root",
              pkey=paramiko.Ed25519Key.from_private_key_file(key), timeout=25)
    return c

def fetch_on(host, port, key):
    """在 host 上下载并校验 geoip.dat, 返回本地字节; 失败返回 None"""
    c = conn(host, port, key)
    for url in URLS:
        print(f"  [{host}] try {url}")
        rc = (c.exec_command(
            f"rm -f /tmp/geo_dl.dat; curl -sL --connect-timeout 15 --max-time 90 -o /tmp/geo_dl.dat "
            f"-w 'HTTP=%{{http_code}} SIZE=%{{size_download}}' '{url}'; echo; head -c4 /tmp/geo_dl.dat | od -An -tx1",
            timeout=150))[1]
        out = rc.read().decode(errors="replace").strip()
        print("   ", out)
        if "SIZE=0" in out or "HTTP=000" in out or "HTTP=404" in out:
            continue
        # 先把下载文件放入资产目录, 再校验(否则 xray -test 用的是旧 geoip.dat, 无法验证新文件)
        c.exec_command(
            "mkdir -p /usr/local/share/xray /usr/local/etc/xray; "
            "cp /tmp/geo_dl.dat /usr/local/share/xray/geoip.dat; "
            "cp /tmp/geo_dl.dat /usr/local/etc/xray/geoip.dat", timeout=30)
        # 校验: xray 真实加载 geoip:cn
        test = (c.exec_command(
            "cp /usr/local/etc/xray/config.json /tmp/cn_t.json 2>/dev/null; "
            "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\" 2>/dev/null; "
            "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", timeout=60))[1]
        t = test.read().decode(errors="replace").strip()
        print("    [xray test geoip:cn]", t)
        if "code not found" not in t:
            # 读取文件字节
            sftp = c.open_sftp()
            buf = b""
            with sftp.open("/tmp/geo_dl.dat", "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    buf += chunk
            sftp.close()
            c.close()
            return buf
        # 文件不对, 继续下一个源 (并清理错误文件, 避免污染)
        c.exec_command("rm -f /usr/local/share/xray/geoip.dat /usr/local/etc/xray/geoip.dat", timeout=15)
    c.close()
    return None

def install_on_cn(buf):
    c = conn(CN, CN_PORT, CN_KEY)
    sftp = c.open_sftp()
    for d in ("/usr/local/share/xray/geoip.dat", "/usr/local/etc/xray/geoip.dat"):
        with sftp.open(d, "wb") as f:
            f.write(buf)
    sftp.close()
    # CN 上最终校验
    t = (c.exec_command(
        "cp /usr/local/etc/xray/config.json /tmp/cn_t.json; "
        "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\"; "
        "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", timeout=60))[1]
    print("[CN xray test geoip:cn]", t.read().decode(errors="replace").strip())
    c.close()

if __name__ == "__main__":
    for host, port, key in [(SG, SG_PORT, SG_KEY), (RU, RU_PORT, RU_KEY), (CN, CN_PORT, CN_KEY)]:
        print(f"=== fetch on {host} ===")
        try:
            buf = fetch_on(host, port, key)
        except Exception as e:
            print("   connect/exec error:", e); buf = None
        if buf:
            print(f">>> got valid geoip.dat ({len(buf)} bytes) from {host}")
            install_on_cn(buf)
            print("INSTALL_DONE")
            break
        else:
            print(f"--- no valid geoip.dat from {host}, try next")
    else:
        print("ALL_FAILED")
