#!/usr/bin/env bash
#
# build-in-docker.sh [<image>] - libngsildpep.so built for the gateway's system (default debian:12, which
# apache/apisix:3.17.0-debian is): the Cor-Libs and coraine read-only from beside this repository, copied and
# built inside the container; the library written to ./dist/<image>/libngsildpep.so. Nothing of the clones'
# own build directories is touched.
#
# Copyright 2026 Seamware
# SPDX-License-Identifier: Apache-2.0
#
set -euo pipefail
IMAGE=${1:-debian:12}
HERE=$(cd "$(dirname "$0")" && pwd)
PARENT=$(cd "$HERE/.." && pwd)
OUT=$HERE/dist/${IMAGE//[:\/]/-}
mkdir -p "$OUT"

docker run --rm -v "$PARENT:/src:ro" -v "$OUT:/out" "$IMAGE" bash -c '
  set -e
  apt-get update -qq > /dev/null && apt-get install -y -qq gcc make libssl-dev > /dev/null
  mkdir -p /build/coraine/src/lib /build/coraine/src/plugins/auth
  for l in corJson corTree corAlloc corLog corBase corArgs; do cp -r /src/$l /build/$l; rm -rf /build/$l/obj; done
  mkdir -p /build/corNgsild && cp /src/corNgsild/*.h /build/corNgsild/      # the LdOp bits: headers only
  cp -r /src/coraine/src/lib/plugin /build/coraine/src/lib/plugin
  cp -r /src/coraine/src/plugins/auth/fdsc /build/coraine/src/plugins/auth/fdsc
  cp -r /src/apisix-ngsild /build/apisix-ngsild; rm -rf /build/apisix-ngsild/obj /build/apisix-ngsild/dist /build/apisix-ngsild/libngsildpep.so
  for l in corJson corTree corAlloc corLog corBase; do make -s -C /build/$l BUILD=release obj/release/lib$l.a > /dev/null; done
  make -s -C /build/apisix-ngsild COR_LIBS=/build > /dev/null
  cp /build/apisix-ngsild/libngsildpep.so /out/
'
echo "build-in-docker.sh: $OUT/libngsildpep.so"
objdump -T "$OUT/libngsildpep.so" | grep -o "GLIBC_[0-9.]*" | sort -uV | tail -1
