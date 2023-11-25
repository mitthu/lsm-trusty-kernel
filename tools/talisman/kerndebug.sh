#!/bin/bash
# Debug kernel in Qemu
#
# Ask compiler to *NOT* optimize:
# #pragma GCC push_options
# #pragma GCC optimize ("O0")
# ...(function)
# #pragma GCC pop_options

SRC=/srv/local/trusty
DISK=/srv/local/diskimg/kernroot.qcow2

# Paramas for security config
APPARMOR=""
SELINUX="selinux=1 security=selinux"
TOMOYO="security=tomoyo"
LSM=$APPARMOR

function run_kern {
        sudo qemu-system-x86_64 \
                -kernel "$SRC/arch/x86_64/boot/bzImage" \
                -append "console=ttyS0 nokaslr root=/dev/sda rw single $LSM" \
                -nographic \
                -hda "$DISK" \
                -m 512 \
                -s -S
}

function run_gdb {
        # hack: long mode bug (needs one disconnect)
        gdb "$SRC/vmlinux" \
                -batch \
                -ex "set debug remote 1" \
                -ex "set architecture i386:x86-64" \
                -ex "target remote :1234" \
                -ex 'b start_kernel' -ex 'c' -ex 'disconnect'

        # connect again
        gdb "$SRC/vmlinux" \
                -ex "set debug remote 1" \
                -ex "set architecture i386:x86-64" \
                -ex "target remote :1234"
}

function usage {
        printf "Usage:\n"
        printf "  $(basename $0) [ -k (default) | -g | -h ] [ -a | -s | -t ] \n"
        printf "    -g  connect over gdb\n"
        printf "    -k  run kernel in qemu (default)\n"
        printf "    -a  enable apparmor (default)\n"
        printf "    -s  enable selinux\n"
        printf "    -t  enable tomoyo\n"
        printf "    -h  print help\n"
}

# Default command
CMD=run_kern

# Parse args
while getopts "gkasth" opt; do
    case $opt in
        h)
                CMD=usage
                ;;
        g)
                CMD=run_gdb
                ;;
        a)
                LSM=$APPARMOR
                ;;
        s)
                LSM=$SELINUX
                ;;
        t)
                LSM=$TOMOYO
                ;;
        k|*)
                CMD=run_kern
                ;;
    esac
done
shift $((OPTIND-1))

# Run command
$CMD
