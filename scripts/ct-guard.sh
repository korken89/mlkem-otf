#!/usr/bin/env bash
# Links every operation (guard/) for Cortex-M0, M3, M4 and M33 at opt-level 2, 3, s and z, and at
# s without LTO and with 16 codegen units, and checks the machine code. The cores other than the
# M33 build core from source.
#
# The checked functions are the guard's main, the functions that hold code of this crate, from
# its own source lines or inlined, the functions of ctutils and cmov, also their trait impls, and
# every function that a checked function calls, also the outlined ones (OUTLINED_FUNCTION_*). A
# call is a direct call or tail call, or an indirect call through a register that the caller
# loads with a function address from a literal pool or with movw and movt. Any other indirect
# call fails. Not followed are the SHA-3 crates (keccak, sponge-cursor, sha3, shake, digest), the
# panic functions of core and the formatting of their messages, which only run after a branch in
# the caller, and these compiler-builtins helpers:
# - copy and fill (memcpy, memmove, memset, memclr) and unaligned load and store (uread,
#   uwrite), which take the same path for all data.
# - division, which the division check below covers at each call.
# - 64-bit shifts (llsl, llsr, lasr), which branch on the shift amount. A checked function may
#   only call them from the SHA-3 padding functions, which shift by the public absorb position,
#   or from an outlined function that is only called from these.
# Every other helper is followed. Every instruction in a checked function is checked, whatever
# source line it comes from.
#
# - Division: its time depends on the operands on Cortex-M, so a division must not touch secrets
#   (KyberSlash). At opt-level 2, 3 and s with LTO there must be no division instruction or
#   helper anywhere in the binary. At z, without LTO, and on the Cortex-M0 that has no long
#   multiply to divide by a constant, core and the SHA-3 crates keep divisions of public slice
#   lengths. There the checked functions may only divide on core's slice lines and in
#   `div_ceil`, which counts chunks.
# - Branches: a conditional branch, IT block or jump table in a checked function must come from
#   a line listed in guard/public-branches.txt, which holds the lines that branch on public data
#   only (loop counters, lengths, the public key). Lines of this repository are matched by file
#   and text, or also by line number where the file has the text more than once, lines of core
#   and other crates by path and line number. An instruction without a source line (line 0) is
#   matched by the innermost inlined function it belongs to. The lines come from the line table,
#   since llvm-objdump shows the line before for line 0. guard/branch-counts.txt pins how many
#   branches each line has in each build, so that a new branch on a listed line fails too.
#   `BLESS=1` rewrites it.
# - Long multiplies (umull, smull, umlal, smlal) end early for small operands on the Cortex-M3,
#   so a checked function must have none, except on the lines above where they divide public
#   lengths by a constant.
# - Panics: at opt-level 2, 3 and s with LTO none may be reachable, also with overflow checks
#   on. At z and without LTO, small generic functions stay out of line with panic branches that
#   are dead at their call sites, so panics are not checked there.
# - Every instruction must decode for the core, so that nothing is skipped.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/guard"

# target, CPU and whether core is built from source
targets=(
    "thumbv8m.main-none-eabihf cortex-m33 0"
    "thumbv7em-none-eabi cortex-m4 1"
    "thumbv7m-none-eabi cortex-m3 1"
    "thumbv6m-none-eabi cortex-m0 1"
)
division='\t((u|s)div(\.w)?|vdiv\.f[0-9]+|vsqrt\.f[0-9]+)\t|<(__aeabi_(u?idiv|u?idivmod|[ul]ldivmod)|__(u?div|u?mod)[sd]i3)>'
# Conditional branches, IT blocks, and jump tables (tbb, tbh and writes to pc other than pop)
branch='\t(b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.[wn])?|cbn?z|it[te]{0,3}|tb[bh](\.w)?)\t|\t[a-z]+(\.[wn])?\tpc, '
long_multiply='\t(u|s)(mull|mlal)\t'
# The lines that divide public lengths or shift by a public amount, the shift helpers, and the
# functions that are not followed, see above
length_lines='/core/src/(slice/|num/uint_macros\.rs:37(88|89)$)'
shift_lines='/(sha3-[0-9.]+/src/utils\.rs:13|shake-[0-9.]+/src/lib\.rs:82)$|^line 0 in (sha3::utils::pad::<|<shake::Shake<[0-9]+>>::pad$)'
shift='<__aeabi_l(lsl|lsr|asr)>'
unchecked='^<<?(__aeabi_(mem(cpy|move|set|clr)[48]?|uread[48]|uwrite[48]|u?idiv(mod)?|[ul]ldivmod|l(lsl|lsr|asr))>|mem(cpy|move|set)>|core::panicking::|core::slice::index::slice_index_fail>|core::result::unwrap_failed|core::option::(unwrap|expect)_failed|core::(fmt|str)::|[a-z0-9]+ as core::fmt::[A-Za-z]+>::fmt>|[a-z0-9]+>::_fmt_inner|(keccak|sponge_cursor|sha3|shake|digest)::)'
status=0
mkdir -p target
: > target/branch-counts.txt

for entry in "${targets[@]}"; do
    read -r target cpu build_std <<< "$entry"
    for variant in 2 3 s z 2-overflow 3-overflow s-overflow s-split; do
        opt=${variant%%-*}
        dir=target/$target/opt-$variant
        name="$cpu opt-level $variant"
        mkdir -p "$(dirname $dir)"
        args=(--release --quiet --target "$target" --target-dir "$dir")
        all=1
        if [ "$opt" = z ] || [ "$variant" = s-split ]; then
            args+=(--features allow-panic)
            all=0
        fi
        if [ "$cpu" = cortex-m0 ]; then
            all=0
        fi
        env=(CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt")
        label="opt-level $opt"
        case $variant in
        *-overflow)
            env+=(CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true)
            label+=" with overflow checks"
            ;;
        *-split)
            env+=(CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16)
            label+=" without LTO and with 16 codegen units"
            ;;
        esac
        if [ "$build_std" = 1 ]; then
            # build-std is unstable, but rust-src comes with the pinned toolchain
            env+=(RUSTC_BOOTSTRAP=1)
            args+=(-Zbuild-std=core)
        fi
        if ! env "${env[@]}" cargo build "${args[@]}" 2> $dir.log; then
            if grep -q mlkem_otf_has_a_reachable_panic $dir.log; then
                echo "$name: a panic is reachable"
            else
                cat $dir.log
            fi
            status=1
            continue
        fi
        # Raw bytes, so that the 0xd4d4 padding between functions is not read as a branch
        llvm-objdump -d -l --demangle --mcpu="$cpu" $dir/$target/release/ct-guard > $dir.dis
        # The line and the innermost inlined function of each instruction that a check keys by
        # line, from the line table. llvm-objdump prints no line for line 0, so there it shows
        # the line before.
        PAT="$branch|$division|$long_multiply|$shift|<OUTLINED_FUNCTION_" awk '
            /^ *[0-9a-f]+:/ && $0 ~ ENVIRON["PAT"] { print "0x" substr($1, 1, length($1) - 1) }
        ' $dir.dis | llvm-addr2line -e $dir/$target/release/ct-guard -a -f -i -C | awk '
            /^0x/ { a = tolower($1); sub(/^0x0*/, "", a); n = 0; next }
            ++n == 1 { f = $0 }
            n == 2 { sub(/ \(discriminator [0-9]+\)$/, ""); print a "\t" $0 "\t" f }
        ' > $dir.lines
        hits=$(RE="$division" BRANCH="$branch" MUL="$long_multiply" UNCHECKED="$unchecked" \
            LENGTHS="$length_lines" SHIFT="$shift" SHIFTS="$shift_lines" ROOT="$root/" ALL=$all \
            CPU="$cpu" COUNTS=$dir.counts CHECKED=$dir.checked STATUS=$dir.status \
            LINES=$dir.lines awk '
            BEGIN {
                while ((getline l < "public-branches.txt") > 0)
                    if (l !~ /^(#|$)/) public[l] = 1
                printf "" > ENVIRON["COUNTS"]
                while ((getline l < ENVIRON["LINES"]) > 0) {
                    split(l, e, "\t")
                    at[e[1]] = (e[2] ~ /:0$/) ? "" : e[2]
                    scope[e[1]] = e[3]
                }
            }
            # The key of a location in public-branches.txt.
            function key(line, at, file, n, l) {
                if (line == "")
                    return "(no source line)"
                if (line ~ /^line 0 in /)
                    return line
                if (index(line, ENVIRON["ROOT"]) != 1) {
                    sub(/^.*\/library\//, "", line)
                    sub(/^.*\/registry\/src\/[^\/]+\//, "", line)
                    return line
                }
                split(substr(line, length(ENVIRON["ROOT"]) + 1), at, ":")
                file = at[1]
                sub(/^src\//, "", file)
                if (!(file in text)) {
                    n = 0
                    while ((getline l < (ENVIRON["ROOT"] at[1])) > 0) {
                        src[file, ++n] = l
                        gsub(/^[ \t]+|[ \t]+$/, "", l)
                        lines[file, l]++
                    }
                    text[file] = 1
                }
                l = src[file, at[2]]
                gsub(/^[ \t]+|[ \t]+$/, "", l)
                return lines[file, l] > 1 ? file ":" at[2] ": " l : file ": " l
            }
            # An address as lowercase hex without leading zeros.
            function hex(s) {
                sub(/^0x/, "", s)
                sub(/^0+/, "", s)
                return tolower(s)
            }
            # The address of the function that a Thumb code pointer points to.
            function code(s, d) {
                s = hex(s)
                d = substr(s, length(s))
                return substr(s, 1, length(s) - 1) \
                    substr("0022446688aaccee", index("0123456789abcdef", d), 1)
            }
            function pad4(s) {
                s = hex(s)
                return substr("0000", length(s) + 1) s
            }
            # Adds the callees of the checked functions until none is new.
            function follow(k, e, changed, g) {
                for (k in literal) {
                    split(k, e, SUBSEP)
                    if (e[2] in word) loaded[e[1], code(word[e[2]]), e[3]] = 1
                }
                for (k in loaded) {
                    split(k, e, SUBSEP)
                    if (!(e[2] in start)) continue
                    call[e[1], e[2]] = 1
                    address_in[e[1], e[3]] = 1
                }
                for (g in root) checked[g] = 1
                do {
                    changed = 0
                    for (k in call) {
                        split(k, e, SUBSEP)
                        if (!(e[1] in checked) || !(e[2] in start)) continue
                        g = start[e[2]]
                        if (g in checked || g ~ ENVIRON["UNCHECKED"]) continue
                        checked[g] = 1
                        changed = 1
                    }
                } while (changed)
                printf "" > ENVIRON["CHECKED"]
                for (g in checked) print g > ENVIRON["CHECKED"]
            }
            FNR != NR && !followed { follow(); followed = 1 }
            />:$/ {
                f = substr($0, length($1) + 2)
                sub(/:$/, "", f)
                if (FNR == NR) start[hex($1)] = f
                line = ""
                next
            }
            /^; \// { line = $2 }
            # The first pass finds the roots and the calls.
            FNR == NR {
                if (f ~ /(mlkem_otf|ctutils|cmov)::/ || f == "<ct_guard::__cortex_m_rt_main>" \
                    || index(line, ENVIRON["ROOT"] "src/") == 1)
                    root[f] = 1
                if (!/^ *[0-9a-f]+:/) next
                split($0, p, "\t")
                if (p[2] == ".word") word[hex(substr($1, 1, length($1) - 1))] = p[3]
                else if (p[2] ~ /^(bl?|b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le))(\.[wn])?$|^cbn?z$/ \
                    && match(p[3], /0x[0-9a-f]+ </))
                    call[f, hex(substr(p[3], RSTART, RLENGTH - 2))] = 1
                else if (p[2] ~ /^ldr(\.w)?$/ && p[3] ~ /\[pc, / && match(p[3], /@ 0x[0-9a-f]+/)) {
                    split(p[3], a, ",")
                    literal[f, hex(substr(p[3], RSTART + 2, RLENGTH - 2)), a[1]] = 1
                }
                else if (p[2] == "movw" && split(p[3], a, /, #/) == 2)
                    movw[f, a[1]] = pad4(a[2])
                else if (p[2] == "movt" && split(p[3], a, /, #/) == 2 && ((f, a[1]) in movw))
                    loaded[f, code(pad4(a[2]) movw[f, a[1]]), a[1]] = 1
                else if (p[2] ~ /^bl?x$/ && p[3] ~ /^r([0-9]|1[0-2])$/)
                    indirect[f, p[3]] = 1
                next
            }
            !/^ *[0-9a-f]+:/ { next }
            # The line of the instruction, empty for line 0, and where it is, which for line 0 is
            # the innermost inlined function
            {
                addr = hex(substr($1, 1, length($1) - 1))
                loc = (addr in at) ? at[addr] : line
                where = (loc == "" && scope[addr] !~ /^(\?\?)?$/) ? "line 0 in " scope[addr] : loc
            }
            # The call sites of the outlined functions
            match($0, /<OUTLINED_FUNCTION_[0-9]+>/) { site[substr($0, RSTART, RLENGTH), where] = 1 }
            /<unknown>/ { print "  undecoded in " f "\n   " $0; next }
            /\t\.(word|short|byte)\t/ { next }
            $0 ~ ENVIRON["RE"] && (ENVIRON["ALL"] || (f in checked && where !~ ENVIRON["LENGTHS"])) {
                print "  division in " f " " where "\n   " $0
            }
            !(f in checked) { next }
            { instructions++ }
            $0 ~ ENVIRON["BRANCH"] && $2 != "d4d4" {
                k = key(where)
                if (k in public)
                    count[k]++
                else
                    print "  branch not in public-branches.txt in " f "\n   " k "\n   " $0
            }
            $0 ~ ENVIRON["SHIFT"] && where !~ ENVIRON["SHIFTS"] {
                if (loc == "" && f ~ /^<OUTLINED_FUNCTION_[0-9]+>$/)
                    shifts_in[f] = 1
                else
                    print "  shift helper call in " f " " where "\n   " $0
            }
            ENVIRON["CPU"] == "cortex-m3" && $0 ~ ENVIRON["MUL"] && where !~ ENVIRON["LENGTHS"] {
                print "  long multiply in " f " " where "\n   " $0
            }
            END {
                for (k in count) printf "%5d %s\n", count[k], k > ENVIRON["COUNTS"]
                for (k in indirect) {
                    split(k, e, SUBSEP)
                    if (e[1] in checked && !(k in address_in))
                        print "  indirect call to an unknown function in " e[1] " through " e[2]
                }
                for (k in site) {
                    split(k, e, SUBSEP)
                    if (e[1] in shifts_in && e[2] !~ ENVIRON["SHIFTS"])
                        print "  shift helper call in " e[1] " called from " e[2]
                }
                n = 0
                for (g in checked) n++
                printf "%d instructions in %d functions\n", instructions, n > ENVIRON["STATUS"]
            }
        ' $dir.dis $dir.dis)
        {
            echo "# $name"
            LC_ALL=C sort -k 2 $dir.counts
        } >> target/branch-counts.txt
        if [ -n "$hits" ]; then
            echo "$name: failed:"
            echo "$hits"
            status=1
        fi
        echo "$target ($cpu) $label: checked $(cat $dir.status)"
    done
done
if [ "${BLESS:-0}" = 1 ]; then
    cp target/branch-counts.txt branch-counts.txt
elif ! diff -u branch-counts.txt target/branch-counts.txt; then
    echo "The branches per line differ from guard/branch-counts.txt"
    status=1
fi
exit $status
