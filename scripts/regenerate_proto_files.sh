#!/usr/bin/env sh

set -x

touch ostrich/build.rs
PROTO_GEN=1 cargo build -p ostrich
