#!/usr/bin/env bash
#
# sameAsFdsc.sh [--keep] - ngsild-pep decides as coraine's --auth fdsc does: coraine's test/fdscDiff cases (the
# connector's tokens, vocabulary and combination rules) sent to APISIX with ngsild-pep in front of a broker
# without --auth, and to coraine with --auth fdsc - the same keys, the same policies - the answers compared by
# class (fdscDiff.py). Expected: no difference at all - the same code decides.
#
# Needs: docker (compose), python3, curl, coraine installed, dist/debian-12/libngsildpep.so
# (./build-in-docker.sh), a coraine checkout beside this repository. Ports: 1027, 1028 (brokers), 7740
# (verifier stand-in), 9080 (APISIX).
#
# Copyright 2026 Seamware
# SPDX-License-Identifier: Apache-2.0
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
CORAINE=${CORAINE:-$HERE/../../coraine}
TOOLS=$CORAINE/test/funcTests/tools
DIFF=$CORAINE/test/fdscDiff
LIB=${NGSILD_LIB:-$HERE/../dist/debian-12/libngsildpep.so}
export NGSILD_WORK=${NGSILD_WORK:-/tmp/sameAsFdsc}
export NGSILD_ROUTES=$HERE/routes-ngsild.yaml
VERIFIER=http://localhost:7740
COMPOSE="docker compose -p ngsildpep -f $HERE/docker-compose.yml"
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1
PIDS=()

die() { echo "sameAsFdsc: $*" >&2; exit 2; }
await() { local s=$1; shift; for _ in $(seq 1 $((s * 5))); do "$@" > /dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
cleanup() {
  [ $KEEP = 1 ] && return
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  $COMPOSE down > /dev/null 2>&1
}
trap cleanup EXIT

[ -f "$LIB" ] || die "no $LIB - ./build-in-docker.sh"
rm -rf "$NGSILD_WORK" && mkdir -p "$NGSILD_WORK"
cp "$LIB" "$NGSILD_WORK/"
cp "$DIFF/policies.json" "$NGSILD_WORK/policies.json"

python3 "$TOOLS/ftJwt.py" key --out "$NGSILD_WORK" --name k1 --alg RS256 > /dev/null || die "no key"
python3 "$TOOLS/ftJwt.py" key --out "$NGSILD_WORK" --name k2 --alg ES256 > /dev/null || die "no key"
python3 "$TOOLS/ftJwt.py" jwks --out "$NGSILD_WORK/jwks.json" "$NGSILD_WORK/k1.jwk" "$NGSILD_WORK/k2.jwk"
echo '[]' > "$NGSILD_WORK/papListing.json"
chmod -R a+rX "$NGSILD_WORK"                         # APISIX runs as its own user in the container

python3 "$TOOLS/ftVerifier.py" --port 7740 --dir "$NGSILD_WORK" > "$NGSILD_WORK/verifier.log" 2>&1 &
PIDS+=($!)

#
# The same options for both: fdsc.so in the broker, and in the gateway
#
ARGS=( --fdscJwks "$NGSILD_WORK/jwks.json" --fdscPolicies "$NGSILD_WORK/policies.json" --fdscIssuer "$VERIFIER" --fdscOrganization did:web:provider )
GWARGS=$(printf '"%s", ' --fdscJwks /opts/ngsild/jwks.json --fdscPolicies /opts/ngsild/policies.json --fdscIssuer "$VERIFIER" --fdscOrganization did:web:provider)
sed -e "s|@WORKERS@|1|" -e "s|@ARGS@|${GWARGS%, }|" "$HERE/config.yaml.in" > "$NGSILD_WORK/config.yaml"

coraine -fg --port 1027 --database corDB > "$NGSILD_WORK/plain.log" 2>&1 &
PIDS+=($!)
coraine -fg --port 1028 --database corDB --auth fdsc "${ARGS[@]}" > "$NGSILD_WORK/coraine.log" 2>&1 &
PIDS+=($!)

$COMPOSE up -d > "$NGSILD_WORK/compose.log" 2>&1 || { cat "$NGSILD_WORK/compose.log"; die "compose up"; }

TOKEN=$(python3 "$TOOLS/ftJwt.py" sign --key "$NGSILD_WORK/k1.pem" --iss "$VERIFIER")
ready() { [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$1/ngsi-ld/v1/entities/urn:ngsi-ld:EnergyReport:1")" = 404 ]; }
await 60 ready http://localhost:9080 || { $COMPOSE logs apisix | tail -20; die "APISIX with ngsild-pep does not let the first case through"; }
await 30 ready http://localhost:1028 || die "coraine does not let the first case through - $NGSILD_WORK/coraine.log"

python3 "$DIFF/fdscDiff.py" --apisix http://localhost:9080 --coraine http://localhost:1028 --cases "$DIFF/cases.json" \
        --keys "$NGSILD_WORK" --iss "$VERIFIER"
