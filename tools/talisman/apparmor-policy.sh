#!/bin/bash
# Generate apparmor policy files

LMBENCH=/srv/local/lmbench-3.0-a9
LMBENCH_BINS=$LMBENCH/bin/x86_64-linux-gnu/
AA_POLICY=/srv/local/lsm/apparmor/lmbench.apparmor

function aa_gen {
        echo "<> generate aa policy"
        local files=$(find "${LMBENCH_BINS}" -type f -executable)

        mkdir -p $(dirname $AA_POLICY)
        echo >$AA_POLICY "#include <tunables/global>"
        for f in $files; do
                # To deny everything, use: 
                # deny /** rwx,
                echo >>$AA_POLICY "\"$f\" {
                        #include <abstractions/base>
                        capability,
                        network,
                        mount,
                        remount,
                        umount,
                        pivot_root,
                        ptrace,
                        signal,
                        dbus,
                        unix,
                        file,
                }"
        done
}

function aa_load {
        echo "<> load aa policy: ${AA_POLICY}"
        sudo apparmor_parser -r $AA_POLICY
}

function aa_remove {
        echo "<> remove aa policy: ${AA_POLICY}"
        sudo apparmor_parser -R $AA_POLICY
}

function run_lmbench {
        echo "<> run lmbench"
        pushd $LMBENCH
        make rerun
        popd
}

function usage {
        printf "Usage:\n"
        printf "  $(basename $0) -[blr]\n"
        printf "    -b  run lmbench\n"
        printf "    -l  gen and load policy\n"
        printf "    -r  unload policy\n"
}

# Parse args
while getopts "lbr" opt; do
    case $opt in
        l)
                aa_gen
                aa_load
                ;;
        b)
                run_lmbench
                ;;
        r)
                aa_remove
                ;;
        *)
                usage
                exit 1
                ;;
    esac
done
shift $((OPTIND-1))
