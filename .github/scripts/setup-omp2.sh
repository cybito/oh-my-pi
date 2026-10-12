#!/usr/bin/env bash
# Input: audit, debug or release. Output: native tools in GITHUB_PATH.
# Side effects: installs packages ONLY on disposable GitHub-hosted runners.
# Permissions: Homebrew on macOS; sudo apt-get on Linux. Refuses local use.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo 'Only run on GitHub Actions.' >&2; exit 1; }
PROFILE="${1:?expected audit, debug or release}"
case "$PROFILE" in audit|debug|release) ;; *) exit 2 ;; esac
TOOLS="$RUNNER_TEMP/omp2-tools"
mkdir -p "$TOOLS"

fetch_tool() {
  local name="$1" url="$2" digest="$3"
  mkdir -p "$TOOLS/$name"
  curl --fail --location --silent --show-error "$url" -o "$TOOLS/$name.tar.gz"
  printf '%s  %s\n' "$digest" "$TOOLS/$name.tar.gz" | shasum -a 256 -c -
  tar -xzf "$TOOLS/$name.tar.gz" -C "$TOOLS/$name"
  rm "$TOOLS/$name.tar.gz"
}

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    brew install bash lld@22 uv zstd ninja
    test -x /opt/homebrew/bin/bash
    LLD_PREFIX="$(brew --prefix lld@22)"
    # These two existing upstream paths must point at the LLVM 22 producer.
    for path in /opt/homebrew/bin/ld64.lld /opt/homebrew/opt/lld; do
      [[ ! -e "$path" || -L "$path" ]] || { echo "Refusing to replace non-symlink $path" >&2; exit 1; }
    done
    ln -sfn "$LLD_PREFIX/bin/ld64.lld" /opt/homebrew/bin/ld64.lld
    ln -sfn "$LLD_PREFIX" /opt/homebrew/opt/lld
    echo /opt/homebrew/bin >> "$GITHUB_PATH"
    fetch_tool cmake https://github.com/Kitware/CMake/releases/download/v3.31.9/cmake-3.31.9-macos-universal.tar.gz eb9d0b2b6a5b900e2f5811326a86ea393a146e4cb2384d15512c226e9c98f8bf
    echo "$TOOLS/cmake/cmake-3.31.9-macos-universal/CMake.app/Contents/bin" >> "$GITHUB_PATH"
    fetch_tool just https://github.com/casey/just/releases/download/1.58.0/just-1.58.0-aarch64-apple-darwin.tar.gz 50ae3e996c974a0bf32ea7d10f495070df33f1b43e0616b2769e3d4821ed8f48
    if [[ "$PROFILE" == debug ]]; then
      fetch_tool nextest https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.148/cargo-nextest-0.9.148-universal-apple-darwin.tar.gz 6c23b7fb4ca82c571fc8dfedbab45bfa773d45918f933170c85d21cd7f4b852b
    fi
    ;;
  Linux:aarch64)
    sudo apt-get update
    sudo apt-get install --no-install-recommends -y pipx zstd ninja-build pkg-config clang-18 lld-18 libclang-dev libpipewire-0.3-dev libasound2-dev
    # GNU ld cannot resolve the Python dependency archives preceding libpython.
    # Match the metadata-driven link contract with LLD's archive backreferences.
    {
      echo CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/clang-18
      echo 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-C link-arg=--ld-path=/usr/bin/ld.lld-18'
      # Cranelift replaces an observed workspace NEON intrinsic with a trap.
      echo CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm
    } >> "$GITHUB_ENV"
    command -v uv >/dev/null || pipx install uv
    echo "$HOME/.local/bin" >> "$GITHUB_PATH"
    fetch_tool cmake https://github.com/Kitware/CMake/releases/download/v3.31.9/cmake-3.31.9-linux-aarch64.tar.gz 09b7127b09e3d3ed5fa894f4e59f6a01112f267da6acc4249e46dba97b14afcb
    echo "$TOOLS/cmake/cmake-3.31.9-linux-aarch64/bin" >> "$GITHUB_PATH"
    fetch_tool just https://github.com/casey/just/releases/download/1.58.0/just-1.58.0-aarch64-unknown-linux-musl.tar.gz 748237128c4c40cbdabc65e841d05ceba13cc23a91eaba395495894c1d9764df
    if [[ "$PROFILE" == debug ]]; then
      fetch_tool nextest https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.148/cargo-nextest-0.9.148-aarch64-unknown-linux-gnu.tar.gz 81469eb963ef883fd590e60189e77d6aba3d91b418591d3391f50fe3e9480d2b
    fi
    ;;
  *) echo 'Expected native macOS ARM64 or GNU Linux ARM64.' >&2; exit 1 ;;
esac
echo "$TOOLS/just" >> "$GITHUB_PATH"
if [[ "$PROFILE" == debug ]]; then echo "$TOOLS/nextest" >> "$GITHUB_PATH"; fi
