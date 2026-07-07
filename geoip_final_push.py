#!/usr/bin/env python3
# 把 SG 上已验证的 geoip.dat 经 scp 推到 CN (先可靠放置 cn 主机私钥到 SG 并校验)
import paramiko

SG="43.156.107.54"; SG_PORT=23022; SG_KEY="ssh_keys_backup/sg_id_ed25519.pem"
CN="47.108.200.193"; CN_PORT=22022; CN_KEY="ssh_keys_backup/cn_id_ed25519.pem"

sg=paramiko.SSHClient(); sg.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sg.connect(SG,port=SG_PORT,username="root",
           pkey=paramiko.Ed25519Key.from_private_key_file(SG_KEY),timeout=25)
def run(cmd,t=120):
    _,o,e=sg.exec_command(cmd,timeout=t); return o.read().decode(errors="replace").strip() or e.read().decode(errors="replace").strip()

# 0) SG 上确认有效文件在
print("SG geo_ss size:", run("stat -c%s /tmp/geo_ss.dat 2>/dev/null || echo NONE"))
# 1) 可靠放置 cn 私钥到 SG 并校验
sftp=sg.open_sftp()
sftp.put(CN_KEY,"/tmp/cn_key.pem")
sftp.close()
print("SG cn_key size:", run("stat -c%s /tmp/cn_key.pem 2>/dev/null || echo NONE"))
run("chmod 600 /tmp/cn_key.pem")
# 2) scp 到 CN 两个资产目录, 捕获输出
out=run(
  f"scp -i /tmp/cn_key.pem -o StrictHostKeyChecking=no -P {CN_PORT} "
  f"/tmp/geo_ss.dat root@{CN}:/usr/local/share/xray/geoip.dat 2>&1; "
  f"scp -i /tmp/cn_key.pem -o StrictHostKeyChecking=no -P {CN_PORT} "
  f"/tmp/geo_ss.dat root@{CN}:/usr/local/etc/xray/geoip.dat 2>&1; "
  f"rm -f /tmp/cn_key.pem; echo PUSH_DONE", t=300)
print("SCP_OUT:\n", out)

# 3) CN 侧校验
cn=paramiko.SSHClient(); cn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cn.connect(CN,port=CN_PORT,username="root",
           pkey=paramiko.Ed25519Key.from_private_key_file(CN_KEY),timeout=25)
def runc(cmd,t=60):
    _,o,e=cn.exec_command(cmd,timeout=t); return o.read().decode(errors="replace").strip() or e.read().decode(errors="replace").strip()
print("CN share size:", runc("stat -c%s /usr/local/share/xray/geoip.dat 2>/dev/null"))
print("CN head:", runc("head -c4 /usr/local/share/xray/geoip.dat | od -An -tx1"))
print("CN test:", runc(
  "cp /usr/local/etc/xray/config.json /tmp/cn_t.json; "
  "python3 -c \"import json;c=json.load(open('/tmp/cn_t.json'));c['routing']['rules'].insert(0,{'type':'field','ip':['geoip:cn'],'outboundTag':'direct'});json.dump(c,open('/tmp/cn_t.json','w'))\"; "
  "xray run -test -config /tmp/cn_t.json 2>&1 | tail -1", t=60))
cn.close(); sg.close()
print("DONE")
