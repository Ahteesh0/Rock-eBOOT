# Rock eBOOT - RK35* Encrypted Boot

Tested on RK3566, RK3576 and RK3588

# WARING
This code may damage your device.
Use at your own risk.
The author assumes no liability for any errors or damaged devices.

# WARNING 2
This is POC edition.
The code doesn't follow best practices. 
Some places contain dirty hacks.
This code has undergone limited testing and may contain errors. 
Use with caution and only if you understand what you are doing and how it works.

## Preparation

Compile U-boot (https://github.com/Ahteesh0/u-boot-orangepi-eboot-poc) 
`make clean && make rk3588_defconfig && CROSS_COMPILE=aarch64-linux-gnu- make  BL31=../rkbin/bin/rk35/rk3588_bl31_v1.48.elf spl/u-boot-spl.bin u-boot.dtb u-boot.itb`

Copy files from compiled u-boot
`tools/mkimage` to `tools/`
`bl31_0x00040000.bin`, `bl31_0x000f0000.bin`, `bl31_0xff100000.bin`, `u-boot.dtb`, `u-boot.its`, `u-boot-nodtb.bin` to `u-boot/`
`u-boot-spl.dtb`, `u-boot-spl-nodtb.bin` to `spl/`

Also copy `rk3588_ddr_lp4_2112MHz_lp5_2400MHz_v1.18.bin` from `rkbin/bin/rk35` to `spl`


Generate keys
```bash
openssl rand 16 > keys/linux_enc/key
openssl rand 16 > keys/uboot_enc/key
openssl rand 16 > keys/spl_enc/key
openssl genrsa -F4 -out keys/linux_sign/dev.key 2048
openssl rsa -in keys/linux_sign/dev.key -pubout > keys/linux_sign/dev.pubkey
openssl req -batch -new -x509 -key keys/linux_sign/dev.key -out keys/linux_sign/dev.crt
openssl genrsa -F4 -out keys/uboot_sign/dev.key 2048
openssl rsa -in keys/uboot_sign/dev.key -pubout > keys/uboot_sign/dev.pubkey
openssl req -batch -new -x509 -key keys/uboot_sign/dev.key -out keys/uboot_sign/dev.crt
openssl genrsa -F4 -out keys/spl_sign/dev.key 2048
openssl rsa -in keys/spl_sign/dev.key > keys/spl_sign/dev.pubkey
openssl req -batch -new -x509 -key keys/spl_sign/dev.key -out keys/spl_sign/dev.crt
```

### WARNING
There is no way to recover SPL sign key if you lose it. 
This key cannot be changed after it is written to OTP.
Do not proceed unless you have made a backup.


## Creating encrypted Linux kernel FIT, U-boot FIT, and U-boot SPL images
These are instructions for creating encrypted images for booting secure firmware.

Initialise build directory
```bash
mkdir out 
rm -rf out/*
mkdir build
rm -rf build/*
cp u-boot/* build
cp spl/* build
cp boot1.its build
```

Place kernel sources to build directory 
`build/Image`: Linux kernel ARM64 boot executable Image
`build/Initrd`: ramdisk, ASCII cpio archive
`build/rk3588s.dtb`: fdt

Create linux FIT
`./tools/mkimage -f build/boot1.its -K build/u-boot.dtb -k keys/linux_sign -E -p 0x1000 -r build/boot1.itb`

Encrypt linux fit
`python3 ./tools/enc_kernel.py keys/linux_enc/key build/boot1.itb out/boot11.eitb`

Add encryption keys to fdt
```bash
fdtput -t bx -p build/u-boot.dtb /encryption/ key $(hexdump -e '16/1 "%02x "' keys/linux_enc/key)
fdtput -t bx -p build/u-boot-spl.dtb /encryption/ key $(hexdump -e '16/1 "%02x "' keys/uboot_enc/key)
```

Prepare binaries for encryption: extend size of each u-boot binary at 0x20 bytes (reserve space for nonce and tag)
`python3 tools/ext_dtb.py`

Create U-boot FIT
`./tools/mkimage -f build/u-boot.its -K build/u-boot-spl.dtb -k keys/uboot_sign -E -p 0x1000 -r build/u-boot.itb`

Encrypt U-boot FIT
`python3 tools/enc_uboot.py keys/uboot_enc/key build/u-boot.itb out/u-boot.eitb` 

Create SPL 
```
cat build/u-boot-spl-nodtb.bin build/u-boot-spl.dtb > build/u-boot-spl.bin
python3 ./tools/packer.py  keys/spl_sign/private_key.pem  keys/spl_enc/key build/rk3588_ddr_lp4_2112MHz_lp5_2400MHz_v1.18.bin build/u-boot-spl.bin  out/idbloader.img
```

Write U-boot to microsd
```
dd if=out/idbloader.img bs=512 seek=64 of=<target sd>
dd if=out/u-boot.eitb bs=512 seek=16384 of=<target sd>
dd if=out/boot1.eitb of=<target sd part 1> #part1 name must be "boot"
```


# Creatin FLASH-keys image
These are instructions for creating an image for flashing OTP keys. The created image contains keys in clear text; do not distribute it.

clean dirs
```bash
mkdir out 
rm -rf out/*
mkdir build
rm -rf build/*
cp u-boot/* build
cp spl/* build
cp boot1.its build
```

For flahsing keys create u-boot FIT signed and encrypted by spl keys:

Prepare binaries for encryption: extend size of each u-boot binary at 0x20 bytes (reserve space for nonce and tag)
`python3 tools/ext_dtb.py`

Create U-boot FIT
`./tools/mkimage -f build/u-boot.its -K build/u-boot-spl.dtb -k keys/spl_sign -E -p 0x1000 -r build/u-boot.itb`

Encrypt U-boot FIT
`python3 tools/enc_uboot.py keys/spl_enc/key build/u-boot.itb out/u-boot_fk.eitb` 

Enable flash key mode
`fdtput -t i -p build/u-boot-spl.dtb /signature/key-dev burn-key-hash 1`

Place encryption key to u-boot-spl.dtb
`fdtput -t bx -p build/u-boot-spl.dtb /encryption/ key $(hexdump -e '16/1 "%02x "' keys/spl_enc/key)`

Create flashkeys image 
```
cat build/u-boot-spl-nodtb.bin build/u-boot-spl.dtb > build/u-boot-spl.bin
./tools/mkimage -n rk3588 -T rksd -d build/rk3588_ddr_lp4_2112MHz_lp5_2400MHz_v1.18.bin:build/u-boot-spl.bin out/flash_keys.img
```

Optional sign image with `rk_sign_tool`

Write to microsd
```
dd if=out/flash_keys.img bs=512 seek=64 of=<target sd>
dd if=out/u-boot.eitb bs=512 seek=16384 of=<target sd>
```


