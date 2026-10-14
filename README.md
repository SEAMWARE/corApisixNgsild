# corApisixNgsild - ngsild-pep, the NGSI-LD API's access decision in APISIX

An APISIX plugin that decides access to an NGSI-LD broker's API in the gateway: the access token checked and
the ODRL policies decided exactly as coraine's `--auth fdsc` decides them (the FIWARE Data Space Connector's
semantics) - by the same C code. `libngsildpep.so` is coraine's `fdsc.so` compiled from its own sources, with
a gateway adapter; the plugin (`lua/apisix/plugins/ngsild-pep.lua`) calls it through LuaJIT's FFI, once per
request. Any NGSI-LD broker can sit behind it.

| | |
|---|---|
| `src/ngsildPep.c` | `ngsildPepInit` (fdsc.so's options) and `ngsildPepDecide` (one decision): an `AuthRequest` built from the gateway's request, fdsc.so's `authenticate` and `authorize` |
| `src/fdscFetchFile.c` | fdsc.so's fetch, files only: nothing below the FFI line does network I/O (a blocking call stalls every request of an nginx worker) |
| `lua/apisix/plugins/ngsild-pep.lua` | the plugin: method, path, query, `Authorization`, `x-stripped-path`, body - one FFI call - let through, or the broker's own 401 / 403 / 503 |
| `build-in-docker.sh` | the library built for the gateway's system (default `debian:12`, which `apache/apisix:3.17.0-debian` is) |
| `test/sameAsFdsc.sh [--pap]` | coraine's `test/fdscDiff` cases against APISIX + ngsild-pep and coraine `--auth fdsc`: 64 cases, 0 differences (2026-10-13) - with the keys and policies from files, and (`--pap`) fetched from the verifier's discovery document and an ODRL-PAP, by the plugin and by coraine |

## Configuration

```yaml
plugins: [ ngsild-pep ]
plugin_attr:
  ngsild-pep:
    lib:  /opts/ngsild/libngsildpep.so
    args: [ "--fdscJwks", "/opts/ngsild/jwks.json", "--fdscPolicies", "/opts/ngsild/policies.json",
            "--fdscIssuer", "http://verifier:3000", "--fdscOrganization", "did:web:provider" ]
```

and `"ngsild-pep": {}` on a route. `args` are fdsc.so's options (coraine `doc/authorization.md` § 3.1);
the keys and the policies are files - or fetched by the plugin in Lua (cosockets, which do not block nginx)
and read by fdsc.so as `mem:jwks` / `mem:policies`:

```yaml
    fetch:
      discovery: http://verifier:3000/services/data-service/.well-known/openid-configuration   # or jwks: <url>
      pap:       http://odrl-pap:8080
      interval:  30
    args: [ "--fdscJwks", "mem:jwks", "--fdscPolicies", "mem:policies", "--fdscIssuer", "http://verifier:3000",
            "--fdscOrganization", "did:web:provider", "--fdscRefresh", "2" ]
```

(`--fdscIssuer` is then required: fdsc.so reads no discovery document of its own.)

## Not yet

- `--fdscNgsild`: deciding on each entity needs the stored entity - the broker's, not the gateway's.
- fdsc.so's log lines (`W:`, `I:`) go nowhere: the library does not initialise corLog.
- One set of keys and policies per gateway (per nginx worker), not per route.
