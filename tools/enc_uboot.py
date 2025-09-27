import Crypto.Cipher.AES as AES
from  Crypto.Random import get_random_bytes 
from hexdump import hexdump
import fdt
from sys import argv 

def enc(key,data,aad):
    cipher=AES.new(key,AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    enc_data=cipher.nonce+tag+ciphertext
    return (enc_data,tag)

if len(argv)!=4:
    print(f"usage: {argv[0]} key uboot.itb uboot.eitb")
    exit(0)
key=open(argv[1],'rb').read()

data=open(argv[2],'rb').read()
aad=b'\x00'*0x10
ebin,aad = enc(key,data[:0x40],aad)
eitb = ebin
ebin,aad = enc(key,data[0x40:0xfc0],aad)
eitb += ebin
ebin, _ = enc(get_random_bytes(0x10),get_random_bytes(len(data)-0x1000),get_random_bytes(0x10)) 
eitb += ebin[0x20:]
images=fdt.parse_dtb(data).get_node('images').nodes
for x in images:
    pos=x.get_property('data-position').data[0]
    size=x.get_property('data-size').data[0]
    print(f'encrypting {x.name} (0x{size:x} bytes)')
    ebin, _  = enc(key,data[pos:pos+size-0x20],aad)
    eitb=eitb[:pos]+ ebin + eitb[pos+size:]

with open(argv[3],'wb') as f:
    f.write(eitb)
