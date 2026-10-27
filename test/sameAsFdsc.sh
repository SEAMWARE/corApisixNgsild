#!/usr/bin/env bash
#
# sameAsFdsc.sh [--pap] [--keep] - ngsild-pep decides as coraine's --auth fdsc does: coraine's test/fdscDiff cases (the
# connector's tokens, vocabulary and combination rules) sent to APISIX with ngsild-pep in front of a broker
# without --auth, and to coraine with --auth fdsc - the same keys, the same policies - the answers compared by
# class (fdscDiff.py). Expected: no difference at all - the same code decides.
#
# --pap: the keys and the policies from the network, as in a connector: the policies in an ODRL-PAP (odrl-pap
# 1.7.3 on PostgreSQL, coraine's test/fdscDiff/docker-compose.yml), the keys from the verifier's discovery
# document - fetched by the plugin (fetch:, mem:jwks / mem:policies), and by coraine (--fdscDiscovery --fdscPap)
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
KEEP=0; PAPMODE=0
for a in "$@"; do case "$a" in --keep) KEEP=1 ;; --pap) PAPMODE=1 ;; *) echo "usage: sameAsFdsc.sh [--pap] [--keep]" >&2; exit 2 ;; esac; done
PAP=http://localhost:8080
PAPCOMPOSE="docker compose -p ngsildpap -f $DIFF/docker-compose.yml"
PIDS=()

die() { echo "sameAsFdsc: $*" >&2; exit 2; }
await() { local s=$1; shift; for _ in $(seq 1 $((s * 5))); do "$@" > /dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
cleanup() {
  [ $KEEP = 1 ] && return
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  $COMPOSE down > /dev/null 2>&1
  [ $PAPMODE = 1 ] && FDSC_DIFF_WORK=$NGSILD_WORK $PAPCOMPOSE down -v > /dev/null 2>&1
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
if [ $PAPMODE = 0 ]; then
  ARGS=( --fdscJwks "$NGSILD_WORK/jwks.json" --fdscPolicies "$NGSILD_WORK/policies.json" --fdscIssuer "$VERIFIER" --fdscOrganization did:web:provider )
  GWARGS=$(printf '"%s", ' --fdscJwks /opts/ngsild/jwks.json --fdscPolicies /opts/ngsild/policies.json --fdscIssuer "$VERIFIER" --fdscOrganization did:web:provider)
  sed -e "s|@WORKERS@|1|" -e "s|@ARGS@|${GWARGS%, }|" "$HERE/config.yaml.in" > "$NGSILD_WORK/config.yaml"
else
  export FDSC_DIFF_WORK=$NGSILD_WORK                 # the compose file names it (its APISIX, not started here)
  $PAPCOMPOSE up -d postgres > "$NGSILD_WORK/pap-compose.log" 2>&1 || die "compose up postgres"
  await 60 $PAPCOMPOSE exec -T postgres psql -h localhost -p 5440 -U postgres -d pap -c "select 1" || die "PostgreSQL did not come up"
  $PAPCOMPOSE up -d pap >> "$NGSILD_WORK/pap-compose.log" 2>&1 || die "compose up pap"
  papUp() { curl -sf "$PAP/policy" > /dev/null && return 0; [ "$($PAPCOMPOSE ps -a --format '{{.State}}' pap)" == "exited" ] && $PAPCOMPOSE start pap > /dev/null 2>&1; return 1; }
  await 120 papUp || die "the PAP did not come up"
  python3 - "$DIFF/policies.json" "$PAP" <<'EOF' || die "the PAP refused a policy"
import json, sys, urllib.request
for p in json.load(open(sys.argv[1])):
    urllib.request.urlopen(urllib.request.Request(sys.argv[2] + "/policy", data=json.dumps(p).encode(), headers={"Content-Type": "application/json"}, method="POST")).read()
EOF
  DISCOVERY=$VERIFIER/services/data-service/.well-known/openid-configuration
  ARGS=( --fdscDiscovery "$DISCOVERY" --fdscPap "$PAP" --fdscOrganization did:web:provider --fdscRefresh 2 )
  GWARGS=$(printf '"%s", ' --fdscJwks mem:jwks --fdscPolicies mem:policies --fdscIssuer "$VERIFIER" --fdscOrganization did:web:provider --fdscRefresh 2)
  sed -e "s|@WORKERS@|1|" -e "s|@ARGS@|${GWARGS%, }|" "$HERE/config.yaml.in" > "$NGSILD_WORK/config.yaml"
  printf '    fetch:\n      discovery: %s\n      pap: %s\n      interval: 2\n' "$DISCOVERY" "$PAP" >> "$NGSILD_WORK/config.yaml"
fi

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
