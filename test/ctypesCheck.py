#!/usr/bin/env python3
# ctypesCheck.py <lib> <jwks> <policies> <issuer> <token> - libngsildpep.so's decisions, without APISIX
import ctypes, sys, time
lib = ctypes.CDLL(sys.argv[1])
class V(ctypes.Structure):
    _fields_ = [("status", ctypes.c_int), ("title", ctypes.c_char * 128), ("detail", ctypes.c_char * 1024), ("www", ctypes.c_char * 512)]
args = ["--fdscJwks", sys.argv[2], "--fdscPolicies", sys.argv[3], "--fdscIssuer", sys.argv[4], "--fdscOrganization", "did:web:provider"]
argv = (ctypes.c_char_p * len(args))(*[a.encode() for a in args])
err = ctypes.create_string_buffer(512)
print("init:", lib.ngsildPepInit(len(args), argv, err, 512), err.value.decode())
tok = sys.argv[5]
v = V()
def decide(method, path, query, authz, body=None):
    b = body.encode() if body else None
    lib.ngsildPepDecide(method.encode(), path.encode(), query.encode() if query else None, authz.encode() if authz else None, None, b, len(b) if b else 0, ctypes.byref(v))
    return v.status, v.title.decode(), v.detail.decode(), v.www.decode()
for i in range(50):                    # the refresh thread reads the files on start: until it has them, 503
    if decide("GET", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", None, "Bearer " + tok)[0] != 503: break
    time.sleep(0.1)
print("token GET     :", decide("GET", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", None, "Bearer " + tok))
print("token PATCH   :", decide("PATCH", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs", None, "Bearer " + tok, '{"speed":{"type":"Property","value":1}}'))
print("token query   :", decide("GET", "/ngsi-ld/v1/entities", "type=Vehicle&limit=20", "Bearer " + tok))
print("no token      :", decide("GET", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", None, None))
print("bad signature :", decide("GET", "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", None, "Bearer " + tok[:-4] + "AAAA"))
