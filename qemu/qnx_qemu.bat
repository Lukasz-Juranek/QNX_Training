qemu-system-x86_64 ^
    -smp 2 ^
    --cpu max ^
    -m 1G ^
    -drive file=disk-qemu.vmdk,if=ide,id=drv0 ^
    -nographic ^
    -kernel ifs.bin ^
    -serial mon:stdio ^
    -no-reboot ^
    -netdev tap,id=net0,ifname="Local Area Connection",script=no,downscript=no ^
    -device virtio-net-pci,netdev=net0,mac=52:54:00:cb:95:f2 


@REM ssh -m hmac-sha2-512 root@169.254.182.97  -o StrictHostKeyChecking=no