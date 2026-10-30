#!/usr/bin/env bash
set -euo pipefail

restore=0
args=()
for arg in "$@"; do
    if [[ "$arg" == "--restore" ]]; then restore=1; else args+=("$arg"); fi
done

if [[ ${#args[@]} -lt 1 || ${#args[@]} -gt 2 ]]; then
    echo "usage: install.sh <fiber-checkout> [debug] [--restore]" >&2
    exit 2
fi

tree="${args[0]}"
profile="${args[1]:-debug}"
if [[ "$profile" != "debug" ]]; then
    echo "install.sh: only the debug profile: the agent pins fiber's debug epoch (2 s), which a $profile build does not run" >&2
    exit 2
fi
wrapper="$(dirname "$(readlink -f "$0")")/fiber-lsp-sdk-agent"

if [[ ! -f "$tree/tests/nodes/start.sh" ]]; then
    echo "install.sh: $tree has no tests/nodes/start.sh, not a fiber tree" >&2
    exit 1
fi

dir="$(cd "$tree" && pwd)/target/$profile"
bin="$dir/fiber-lsp-sdk-agent"
aside="$bin.rust"

if [[ $restore -eq 1 ]]; then
    if [[ -L "$bin" ]]; then
        rm "$bin"
        echo "removed the symlink $bin"
    fi
    if [[ -e "$aside" ]]; then
        mv "$aside" "$bin"
        echo "restored the Rust agent at $bin"
    else
        echo "no $aside to restore"
    fi
    exit 0
fi

mkdir -p "$dir"
if [[ -e "$bin" && ! -L "$bin" ]]; then
    if [[ -e "$aside" ]]; then
        echo "install.sh: $aside already exists, refusing to overwrite it" >&2
        exit 1
    fi
    mv "$bin" "$aside"
    echo "moved the Rust agent aside to $aside"
fi
ln -sfn "$wrapper" "$bin"
echo "linked $bin -> $wrapper"
