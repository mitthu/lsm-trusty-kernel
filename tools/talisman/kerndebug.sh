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

function run_kern {
        sudo qemu-system-x86_64 \
                -kernel "$SRC/arch/x86_64/boot/bzImage" \
                -append "console=ttyS0 nokaslr root=/dev/sda rw single" \
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
        printf "  $(basename $0) [-k (default)] [-g] [-h]\n"
        printf "    -k  run kernel in qemu (default)\n"
        printf "    -g  connect over gdb\n"
        printf "    -h  print help\n"

}

# Parse args
while getopts "kgh" opt; do
    case $opt in
        h)
                usage
                exit 1
                ;;
        g)
                run_gdb
                exit 0
                ;;
        k|*)
                run_kern
                exit 0
                ;;
    esac
done
shift $((OPTIND-1))
