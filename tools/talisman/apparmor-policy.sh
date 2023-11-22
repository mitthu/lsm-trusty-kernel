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

function lmbench_run {
        echo "<> run lmbench"
        pushd $LMBENCH
        make rerun
        popd
}

function lmbench_results {
        echo "<> latest lmbench results"
        pushd "$LMBENCH/results/x86_64-linux-gnu" >/dev/null
        SEP='\t'

        local file=$(ls -t | head -1)
        if ! test -z $file
        then
                echo "<> file: $file"
                local res=$(egrep "Simple (read|write|stat|fstat|open/close):" $file)

                printf "$res" | cut -f2 -d\ | sed 's/://g' | tr '\n' $SEP
                printf "\n"
                printf "$res" | cut -f3 -d\ | tr '\n' $SEP
                printf "\n"
        fi

        popd >/dev/null
}

function usage {
        printf "Usage:\n"
        printf "  $(basename $0) -[blr] -p\n"
        printf "    -b  run lmbench\n"
        printf "    -p  print latest lmbench results\n"
        printf "    -l  gen and load policy\n"
        printf "    -r  unload policy\n"
        printf "    -h  help (this menu)\n"
}

# Parse args
while getopts "lbrph" opt; do
    case $opt in
        l)
                aa_gen
                aa_load
                ;;
        b)
                lmbench_run
                ;;
        p)
                lmbench_results
                ;;
        r)
                aa_remove
                ;;
        h|*)
                usage
                exit 1
                ;;
    esac
done
shift $((OPTIND-1))
