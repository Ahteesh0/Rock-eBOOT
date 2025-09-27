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
    print(f"usage: {argv[0]} key kernel.itb kernel.eitb")
    exit(0)

fdt_key=open(argv[1],'rb').read()

data=open(argv[2],'rb').read()

FDT_HEAD=0x28
FDT=0x800
BIN=0x0

for x in fdt.parse_dtb(data).get_node('images').nodes:
     BIN=max(BIN,x.get_property('data-size').data[0]+x.get_property('data-position').data[0])

aad=b'\x00'*0x10
ebin,aad = enc(fdt_key,data[:FDT_HEAD],aad)
eitb = ebin
ebin,aad = enc(fdt_key,data[FDT_HEAD:FDT],aad)
eitb += ebin
ebin,aad = enc(fdt_key,data[FDT:BIN],aad)
eitb += ebin
ebin, _ = enc(get_random_bytes(0x10),get_random_bytes(len(data)-BIN),get_random_bytes(0x10)) 
eitb += ebin
with open(argv[3],'wb') as f:
    f.write(eitb)


