import struct
from sys import argv
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

magic=b'RKSS'
size=0x180

def pad(b,l):
    return b+b'\x00'*(l-len(b))

def pack(rsakey,aeskey,ddr,spl):
    nonce=get_random_bytes(8)
    aeskey=open(aeskey,'rb').read()
    
    ddr=open(ddr,'rb').read()
    if len(ddr)%0x800:
        ddr+=b'\x00'*(0x800-len(ddr)%0x800)
    a=AES.new(aeskey, AES.MODE_CTR,nonce=nonce)
    ddr=a.encrypt(ddr)
    
    fw=open(spl,'rb').read()
    if len(fw)%0x800:
        fw+=b'\x00'*(0x800-len(fw)%0x800)
    fw=a.encrypt(fw)

    key=RSA.importKey(open(keyfile,'rb').read())
    keyblock=(key.n).to_bytes(0x100)[::-1]
    keyblock+=b'\x00'*0x100
    keyblock+=(key.e).to_bytes(0x10)[::-1]
    keyblock+=(pow(2,2048+132)//key.n).to_bytes(0x100)[::-1]
    keyblock+=b'\x00'*0xf0

    flags=0x1011
    header=pad(struct.pack("<4sIHHIII8s",magic,0,size,2,flags,0,0,nonce),0x78)

    ddr_hash=SHA256.new(ddr).digest()
    header+=struct.pack("<HHIII",4,len(ddr)//0x200,0xffff_ffff,0,0)+b'\x00'*8+ddr_hash+b'\x00'*0x20
    
    fw_hash=SHA256.new(fw).digest()
    header+=struct.pack("<HHIII",4+len(ddr)//0x200,len(fw)//0x200,0xffff_ffff,0x02,len(ddr)//0x10)+b'\x00'*8+fw_hash+b'\x00'*0x20

    header=pad(header,0x200)
    header+=keyblock

    a=PKCS1_PSS.new(key)
    head_hash=SHA256.new(header)
    sign=a.sign(head_hash)

    return header+sign[::-1]+b'\x00'*0x100+ddr+fw


if len(argv)==6:
    with open(argv[5],'wb') as f:
        f.write(pack(argv[1],argv[2],argv[3],argv[4]))
else:
    print(f'usage: {argv[0]} rsa_key.pem aes_key.bin ddr.bin spl.bin out.bin')
