# shellcheck shell=bash
# R49/R55: never write a build product straight onto the operational path.
#
# Every native build in this repository used to compile or copy directly onto the binary
# it was replacing. That is not merely an overwrite - it destroys the old copy before the
# new one is known to be good:
#
#   - `cc -o "$OUT"` keeps the inode and rewrites in place, so a LINK-stage failure
#     unlinks it (measured on cc/clang/g++; a compile-stage failure leaves it alone).
#   - `cp src "$OUT"` opens the destination O_WRONLY|O_TRUNC (measured with strace), so an
#     interrupted copy leaves a truncated file where the binary was. The safetensors
#     binaries are 19 MB and 6 MB, which is a wide window.
#
# harnesses/{aflpp,libfuzzer}/ binaries are covered by .gitignore, so git cannot
# restore them, and rebuilding needs an instrumented onnxruntime .so or an AFL++ toolchain
# the dev machine does not have. The checkers call these builds unconditionally whenever
# the tooling is on PATH - there is no "already exists" skip.
#
# Contract, in the order the helpers are meant to be used:
#
#   staged_target OUT  || exit 1                 # resolve symlink in place, refuse directory
#   staged_new "$OUT" STAGED || exit 1           # sibling of $OUT, recorded for cleanup
#   trap staged_cleanup EXIT                     # every failure path drops the staging file
#   ... build into "$STAGED" ...                 # it is already 0755, so scope gates see it
#   staged_commit "$STAGED" "$OUT" || exit 1     # non-empty + 0755 + atomic rename
#
# Both helpers take the NAME of the variable to assign, not a value to capture. Calling
# them as `x="$(staged_new ...)"` would run them in a subshell, where the cleanup list is
# built and then thrown away - measured: the staging files survived every failure path.
#
# Properties the callers depend on, each pinned by scripts/check_staged_install.sh:
#   1. a failed build leaves the old binary byte-identical
#   2. the staging file is a SIBLING of the target, so the commit is a same-filesystem
#      rename - across filesystems mv is copy+unlink, and a truncated copy is still -x,
#      so the callers' `[[ -x $replay ]]` probes would accept it
#   3. the staging file is 0755 from creation (the gates read it before it is installed)
#      and stays 0755 when installed - not mktemp's 0600 ORed with the linker's +x (0711):
#      0711 has no read permission for group or other, the documented docker build path
#      runs as root, and both engine_mode.sh probes and afl-fuzz's check_binary() read the
#      file - a 0711 binary is misread as uninstrumented
#   4. a build that exits 0 without producing anything never installs a 0-byte file
#   5. a symlinked target keeps its link and the real file behind it is what gets replaced
#      (measured: `cc -o <symlink>` does NOT follow the link either, it replaces the link
#      with a regular file and orphans the target - so this is an improvement, not a
#      restoration of the previous behaviour)
#   6. a directory where the binary belongs fails loudly; `mv file dir/` would succeed and
#      report a false install that set -e cannot catch

# Staging files created so far, so one EXIT trap cleans up a build with several outputs.
STAGED_INSTALL_FILES=()

staged_cleanup() {
    # Preserve the exit status the shell was leaving with. An EXIT trap whose LAST command
    # fails replaces it - measured: a build that exited 101 (cargo) reported 1 when the
    # cleanup rm hit a read-only directory, and the checkers read that rc.
    local __si_rc=$? f
    for f in "${STAGED_INSTALL_FILES[@]+"${STAGED_INSTALL_FILES[@]}"}"; do
        # `|| :` matters: under `set -e` a failing rm inside an EXIT trap aborts the trap
        # before the return below, and the shell exits 1 instead of the real status.
        [ -n "$f" ] && { rm -f "$f" 2>/dev/null || :; }
    done
    return "$__si_rc"
}

# staged_target <varname> -> rewrites that variable to the path to actually write to.
staged_target() {
    # Internal names are __si_-prefixed on purpose: `printf -v` writes to a local of the
    # same name if there is one, so a caller passing `out` or `staged` would silently get
    # nothing back. That bug shipped once here and made failure cases pass for the wrong
    # reason, which is why the caller-variable names are pinned by the check script.
    local __si_var="$1" __si_out __si_real
    # Indirect expansion, not eval: `eval "x=\${$name}"` runs commands when the NAME
    # contains an assignment-default expansion, e.g. `x=$(touch /tmp/pwned)`. Measured.
    case "$__si_var" in
        [!A-Za-z_]*|*[!A-Za-z0-9_]*|'')
            echo "[staged-install] not a valid variable name: $__si_var" >&2; return 2 ;;
        __si_var|__si_out|__si_real|__si_staged|__si_rc|STAGED_INSTALL_FILES)
            # Same reason as staged_new: printf -v would write to this function's own
            # local and the caller would silently get a no-op with rc 0.
            echo "[staged-install] reserved variable name: $__si_var" >&2; return 2 ;;
    esac
    __si_out="${!__si_var}"
    if [ -L "$__si_out" ]; then
        __si_real="$(readlink -f "$__si_out")" || {
            echo "[staged-install] cannot resolve the symlink at $__si_out" >&2
            return 1
        }
        __si_out="$__si_real"
    fi
    if [ -d "$__si_out" ]; then
        echo "[staged-install] target is a directory, not a file: $__si_out" >&2
        return 1
    fi
    printf -v "$__si_var" '%s' "$__si_out"
}

# staged_new <target> <varname> -> assigns a staging path beside the target to varname.
staged_new() {
    local __si_out="$1" __si_var="$2" __si_staged
    case "$__si_var" in
        [!A-Za-z_]*|*[!A-Za-z0-9_]*|'')
            echo "[staged-install] not a valid variable name: $__si_var" >&2; return 2 ;;
        __si_out|__si_var|__si_staged|__si_real|STAGED_INSTALL_FILES)
            # These are this function's own locals; printf -v would write to them and the
            # caller would silently get nothing back. Refuse instead of half-working.
            echo "[staged-install] reserved variable name: $__si_var" >&2; return 2 ;;
    esac
    mkdir -p "$(dirname "$__si_out")" || return 1
    __si_staged="$(mktemp "$__si_out.new.XXXXXX")" || {
        echo "[staged-install] cannot create a staging file beside $__si_out" >&2
        return 1
    }
    # 0755 from the start, not at commit time: the instrumentation gates run on the
    # staging file BEFORE it is installed, and both of them refuse a file they cannot
    # execute or read. mktemp makes it 0600, and a linker that rewrites the file in place
    # keeps that mode - which is how a good build got rejected as uninstrumented.
    chmod 755 "$__si_staged" || return 1
    STAGED_INSTALL_FILES+=("$__si_staged")
    printf -v "$__si_var" '%s' "$__si_staged"
}

# staged_commit <staging> <resolved-target> -> install it, or leave the target untouched.
staged_commit() {
    local staged="$1" out="$2"
    if [ ! -s "$staged" ]; then
        echo "[staged-install] the new $(basename "$out") is empty; $out left unchanged" >&2
        return 1
    fi
    # 0755 is what a fresh `-o <path>` link produces under umask 022 and what the existing
    # binaries carry. Not `chmod +x`: mktemp starts at 0600 and a linker that rewrites the
    # file in place only ORs the exec bits, which would install 0711.
    chmod 755 "$staged" || return 1
    mv -f "$staged" "$out" || {
        echo "[staged-install] cannot install $out" >&2
        return 1
    }
}
