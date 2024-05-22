# Rock eBOOT - RK3588 Encrypted Boot
## Use packer to create encrypted SPL:
You should prepare AES-key in raw-binary format, private RSA key in .pem format, and 2 parts of SPL: DDR.bin and u-Boot-spl.bin. 

Commad format for packer is ` ./packer.py rsa_key.pem aes_key.bin ddr.bin spl.bin out.bin`

