#!/usr/bin/env python3
# 在 SG 下载 v2fly geoip.dat, 直接用 cn 主机私钥从 SG scp 到 CN (服务端到服务端, 不经本机中转大数据)
import paramiko

SG = "43.156.107.54";  SG_PORT = 23022; SG_KEY = "ssh_keys_backup/sg_id_ed25519.pem"
CN = "47.108.200.193"; CN_PORT = 22022; CN_KEY = "ssh_keys_backup/cn_id_ed25519.pem"

URLS = [
    "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
    "https://ghproxy.com/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
    "https://raw.githubusercontent.com/v2fly/geoip/master/geoip.dat",
]

def ssh(host, port, key):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username="root",
              pkey=paramiko.Ed25519Key.from_private_key_file(key), timeout=25)
    return c

def main():
    sg = ssh(SG, SG_PORT, SG_KEY)
    # 1) SG 下载
    for url in URLS:
        print(f"[SG] try {url}")
        rc = sg.exec_command(
            f"rm -f /tmp/geo_ss.dat; curl -sL --connect-timeout 15 --max-time 120 -o /tmp/geo_ss.dat "
            f"-w 'HTTP=%{{http_code}} SIZE=%{{size_download}}' '{url}'; echo; head -c4 /tmp/geo_ss.dat | od -An -tx1",
            timeout=180)[1]
        out = rc.read().decode(errors="replace").strip()
        print("   ", out)
        if "SIZE=0" in out or "HTTP=000" in out or "HTTP=404" in out:
            continue
        # 2) SG 本地校验(先放进资产目录再 test)
        sg.exec_command("mkdir -p /usr/local/share/xray /usr/local/etc/xray; "
                        "cp /tmp/geo_ss.dat /usr/local/share/xray/geoip.dat; "
                        "cp /tmp/geo_ss.dat /usr/local/etc/xray/geoip.dat", timeout=30)
        t = sg.exec_command(
            "cp /usr/local/etc/xray/config.json /tmp/cn_t.json 2>/dev/null; "
            "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\" 2>/dev/null; "
            "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", timeout=60)[1]
        tv = t.read().decode(errors="replace").strip()
        print("   [SG xray test geoip:cn]", tv)
        if "code not found" in tv:
            sg.exec_command("rm -f /usr/local/share/xray/geoip.dat /usr/local/etc/xray/geoip.dat", timeout=15)
            continue
        print(">>> SG 拿到有效 geoip.dat, 准备直传 CN")
        break
    else:
        print("SG 所有源失败"); sg.close(); return

    # 3) 把 cn 主机私钥推到 SG (仅 426 字节, 快), 供 SG scp 到 CN
    sftp = sg.open_sftp()
    sftp.put(CN_KEY, "/tmp/cn_key.pem")
    sftp.close()
    sg.exec_command("chmod 600 /tmp/cn_key.pem", timeout=10)

    # 4) SG 直接 scp 到 CN (服务端到服务端)
    sg.exec_command(
        f"scp -i /tmp/cn_key.pem -o StrictHostKeyChecking=no -P {CN_PORT} "
        f"/tmp/geo_ss.dat root@{CN}:/usr/local/share/xray/geoip.dat; "
        f"scp -i /tmp/cn_key.pem -o StrictHostKeyChecking=no -P {CN_PORT} "
        f"/tmp/geo_ss.dat root@{CN}:/usr/local/etc/xray/geoip.dat; "
        f"rm -f /tmp/cn_key.pem",
        timeout=300)
    print("[SG->CN scp] done")

    # 5) CN 侧最终校验
    cn = ssh(CN, CN_PORT, CN_KEY)
    sz = cn.exec_command("stat -c%s /usr/local/share/xray/geoip.dat 2>/dev/null; head -c4 /usr/local/share/xray/geoip.dat | od -An -tx1")[1].read().decode(errors="replace").strip()
    print("[CN file]", sz)
    t = cn.exec_command(
        "cp /usr/local/etc/xray/config.json /tmp/cn_t.json; "
        "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\"; "
        "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", timeout=60)[1]
    print("[CN xray test geoip:cn]", t.read().decode(errors="replace").strip())
    cn.close(); sg.close()
    print("DONE")

if __name__ == "__main__":
    main()
