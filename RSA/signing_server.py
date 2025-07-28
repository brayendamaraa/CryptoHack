from pwn import *
import json

conn = remote('socket.cryptohack.org', 13374)
conn.recvline()
conn.send(json.dumps({"option": "get_pubkey"}))

get_pubkey = conn.recvline()
idx = get_pubkey.index(b'{')
pubkey = json.loads(get_pubkey[idx:])
print(pubkey)

conn.send(json.dumps({"option": "get_secret"}))
get_secret = conn.recvline()
idx = get_secret.index(b'{')
get_secret = json.loads(get_secret[idx:])
print(get_secret)

secret = get_secret['secret']
sign = {"option": "sign", "msg": secret}
conn.send(json.dumps(sign))
sign = conn.recvline()
idx = sign.index(b'{')
sign = json.loads(sign[idx:])
flag = sign['signature']
flag = flag[2:]
flag = bytes.fromhex(flag)
idx = flag.index(b'{')
flag = flag[idx:]
flag = b'crypto{' + flag + b'}'
print(flag)