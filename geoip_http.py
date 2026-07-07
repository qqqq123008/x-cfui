#!/usr/bin/env python3
# 用 HTTP 把 SG 上的 geoip.dat 传给 CN (绕开 scp 的 libcrypto 密钥格式不兼容):
# SG 临时起 http.server 提供文件, CN 直接 curl 拉取 (CN->SG 出向默认允许)。
import paramiko, time

SG="43.156.107.54"; SG_PORT=23022; SG_KEY="ssh_keys_backup/sg_id_ed25519.pem"
CN="47.108.200.193"; CN_PORT=22022; CN_KEY="ssh_keys_backup/cn_id_ed25519.pem"
PORT=18080

sg=paramiko.SSHClient(); sg.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sg.connect(SG,port=SG_PORT,username="root",
           pkey=paramiko.Ed25519Key.from_private_key_file(SG_KEY),timeout=25)
def run(cmd,t=120):
    _,o,e=sg.exec_command(cmd,timeout=t); return o.read().decode(errors="replace").strip() or e.read().decode(errors="replace").strip()

print("SG geo_ss size:", run("stat -c%s /tmp/geo_ss.dat 2>/dev/null || echo NONE"))
# SG 临时放行端口并起 http 服务(后台)
run(f"ufw allow {PORT}/tcp >/dev/null 2>&1; "
    f"nohup python3 -m http.server {PORT} --directory /tmp >/tmp/geo_http.log 2>&1 & "
    f"sleep 1; echo HTTP_UP")
# 确认服务起来了
print("SG http check:", run(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{PORT}/geo_ss.dat"))

# CN 侧直接 curl 拉取 (SG 公网 IP)
cn=paramiko.SSHClient(); cn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cn.connect(CN,port=CN_PORT,username="root",
           pkey=paramiko.Ed25519Key.from_private_key_file(CN_KEY),timeout=25)
def runc(cmd,t=300):
    _,o,e=cn.exec_command(cmd,timeout=t); return o.read().decode(errors="replace").strip() or e.read().decode(errors="replace").strip()
print("CN pull:", runc(
  f"curl -s --connect-timeout 15 --max-time 280 -o /usr/local/share/xray/geoip.dat "
  f"http://{SG}:{PORT}/geo_ss.dat -w 'share HTTP=%{{http_code}} size=%{{size_download}}\\n'; "
  f"curl -s --connect-timeout 15 --max-time 280 -o /usr/local/etc/xray/geoip.dat "
  f"http://{SG}:{PORT}/geo_ss.dat -w 'etc HTTP=%{{http_code}} size=%{{size_download}}\\n'", t=300))
print("CN share size:", runc("stat -c%s /usr/local/share/xray/geoip.dat 2>/dev/null"))
print("CN head:", runc("head -c4 /usr/local/share/xray/geoip.dat | od -An -tx1"))
print("CN test:", runc(
  "cp /usr/local/etc/xray/config.json /tmp/cn_t.json; "
  "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\"; "
  "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", t=60))

# 清理 SG 临时服务
run(f"pkill -f 'http.server {PORT}' 2>/dev/null; ufw delete allow {PORT}/tcp >/dev/null 2>&1; echo CLEANED")
cn.close(); sg.close()
print("DONE")
