#!/usr/bin/env sh
# This is intended to be used in CI only.

set -ex

echo "Setup toolchain"
toolchain=
if [ -n "$TOOLCHAIN" ]; then
  toolchain=$TOOLCHAIN
else
  toolchain=stable
fi
if [ "$OS" = "windows" ]; then
  : "${TARGET?The TARGET environment variable must be set.}"
  rustup set profile minimal
  rustup update --force "$toolchain-$TARGET"
  rustup default "$toolchain-$TARGET"
else
  rustup set profile minimal
  rustup update --force "$toolchain"
  rustup default "$toolchain"
fi

if [ -n "$TARGET" ]; then
  echo "Install target"
  rustup target add "$TARGET"
fi

if [ -n "$INSTALL_RUST_SRC" ]; then
  echo "Install rust-src"
  rustup component add rust-src
fi

if [ "$OS" = "windows" ]; then
  # Install Npcap
  curl.exe -o "C:/npcap-sdk.zip" "https://npcap.com/dist/npcap-sdk-0.zip"
  powershell.exe -NoP -NonI -Command "Expand-Archive -LiteralPath C:/npcap-sdk.zip -DestinationPath C:/"
  cp "C:/npcap-sdk/Lib/x64/Packet.lib" "C:/Packet.lib"
  cp "C:/npcap-sdk/Lib/x64/Packet.lib" "./Packet.lib"
  curl.exe -o "C:/npcap.exe" "https://github.com/nmap/npcap/releases/download/v0.80/npcap-0.80.exe"
  C:/npcap.exe "/S"
fi

echo "Query rust and cargo versions"
command -v rustc
command -v cargo
command -v rustup
rustc -Vv
cargo -V
rustup -Vv
rustup show

echo "Generate lockfile"
N=5
n=0
until [ $n -ge $N ]
do
  if cargo generate-lockfile; then
    break
  fi
  n=$((n+1))
  sleep 1
done