#!/usr/bin/python3

def ext(fname):
    data=open(fname,'rb').read()
    ext_data=data+b'\x00'*0x20
    with open(fname,'wb') as out_f:
        out_f.write(ext_data)

f=open('build/u-boot.its','r').read().splitlines()
armed=False
fname=''
for x in f:
    if 'data = /incbin/("' in x:
        armed=True
        fname="build/"+x.split('"')[1]
    elif armed and 'compression = "' in x:
        armed=False
        ext(fname)
