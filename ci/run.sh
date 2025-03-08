#!/usr/bin/env sh

# Builds and runs tests for a particular target passed as an argument to this
# script.

set -ex

: "${TOOLCHAIN?The TOOLCHAIN environment variable must be set.}"
: "${OS?The OS environment variable must be set.}"

RUST=${TOOLCHAIN}

echo "Testing Rust ${RUST} on ${OS}"

# FIXME: rustup often fails to download some artifacts due to network
# issues, so we retry this N times.
N=5
n=0
until [ $n -ge $N ]
do
    if rustup override set "${RUST}" ; then
        break
    fi
    n=$((n+1))
    sleep 1
done

case "${OS}" in
    windows*)
        cargo test --all-targets

        cargo test --all-targets --features npcap

        cargo test --all-targets --features npcap-runtime

        cargo test --all-targets --features async-std

        cargo test --all-targets --features smol

        cargo test --all-targets --features tokio
        
        cargo test --all-targets --all-features

        # doc tests must have all features enabled to run
        cargo test --doc --all-features
        ;;
    *)
        # No extra features in any platform other than windows

        cargo test --all-targets

        cargo test --all-targets --features async-std

        cargo test --all-targets --features mio

        cargo test --all-targets --features smol

        cargo test --all-targets --features tokio

        cargo test --all-targets --all-features

        # doc tests must have all features enabled to run
        cargo test --doc --all-features
        ;;
esac
