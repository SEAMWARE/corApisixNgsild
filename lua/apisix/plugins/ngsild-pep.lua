--
-- ngsild-pep.lua - an APISIX plugin: the NGSI-LD API's access decision in the gateway - the token checked and
-- the ODRL policies decided as coraine's --auth fdsc decides them, by the same C code (libngsildpep.so, LuaJIT
-- FFI). For any NGSI-LD broker behind it.
--
-- Configuration - config.yaml, one per gateway (the C side holds one set of keys and policies per worker):
--
--   plugins: [ ngsild-pep ]
--   plugin_attr:
--     ngsild-pep:
--       lib:  /opts/ngsild/libngsildpep.so
--       args: [ "--fdscJwks", "/opts/ngsild/jwks.json", "--fdscPolicies", "/opts/ngsild/policies.json",
--               "--fdscIssuer", "http://verifier:3000", "--fdscOrganization", "did:web:provider" ]
--
-- args are fdsc.so's own options (doc/authorization.md § 3.1 in coraine); the keys and the policies are FILES
-- here - nothing below the FFI line does network I/O. A route enables it with "ngsild-pep": {}.
--
-- Per request: the method, the path, the query string, Authorization, x-stripped-path, the body - one FFI call
-- - and either the request goes on, or the answer is the broker's own: 401 / 403 / 503 with a ProblemDetails
-- (type about:blank) and, for a 401, WWW-Authenticate.
--
-- Copyright 2026 Seamware
-- SPDX-License-Identifier: Apache-2.0
--
local core   = require("apisix.core")
local plugin = require("apisix.plugin")
local ffi    = require("ffi")

local plugin_name = "ngsild-pep"

ffi.cdef[[
typedef struct NgsildPepVerdict
{
  int   status;
  char  title[128];
  char  detail[1024];
  char  wwwAuthenticate[512];
} NgsildPepVerdict;

int ngsildPepInit(int argc, const char** argv, char* errorBuf, int errorBufSize);
int ngsildPepDecide(const char* method, const char* path, const char* query, const char* authorization,
                    const char* strippedPath, const char* body, int bodyLen, NgsildPepVerdict* vP);
]]

local schema = { type = "object", properties = {} }

local attr_schema = {
  type       = "object",
  properties = {
    lib  = { type = "string" },
    args = { type = "array", items = { type = "string" } },
  },
  required   = { "lib", "args" },
}

local _M = {
  version  = 0.1,
  priority = 2600,                                   -- before openid-connect (2599): it decides alone
  name     = plugin_name,
  schema   = schema,
}

local lib                                            -- the C library, once per worker
local verdict                                        -- one result struct per worker, reused: no allocation per request
local initError                                      -- why it could not start - every request is then a 503

function _M.check_schema(conf)
  return core.schema.check(schema, conf)
end

--
-- init - in each worker (and again on a reload: the C side keeps its first set, it says so and goes on)
--
function _M.init()
  if lib ~= nil then
    return
  end

  local attr = plugin.plugin_attr(plugin_name)
  local ok, err = core.schema.check(attr_schema, attr or {})
  if not ok then
    initError = "plugin_attr ngsild-pep: " .. err
    core.log.error(initError)
    return
  end

  local loaded, l = pcall(ffi.load, attr.lib)
  if not loaded then
    initError = "cannot load " .. attr.lib .. ": " .. tostring(l)
    core.log.error(initError)
    return
  end

  local argv = ffi.new("const char*[?]", #attr.args)
  for i, a in ipairs(attr.args) do
    argv[i - 1] = a
  end
  _M.args = attr.args                                -- the strings stay referenced: argv points into them

  local errBuf = ffi.new("char[512]")
  if l.ngsildPepInit(#attr.args, argv, errBuf, 512) ~= 0 then
    initError = "ngsild-pep: " .. ffi.string(errBuf)
    core.log.error(initError)
    return
  end

  lib     = l
  verdict = ffi.new("NgsildPepVerdict")
  core.log.info("ngsild-pep: fdsc.so's decision in the gateway - ", table.concat(attr.args, " "))
end

--
-- access - may the request through
--
function _M.access(conf, ctx)
  if lib == nil then
    return 503, { type = "about:blank", title = "Service Unavailable", status = 503,
                  detail = initError or "ngsild-pep is not initialised" }
  end

  local method = ngx.req.get_method()
  local body   = nil

  if method ~= "GET" and method ~= "HEAD" and method ~= "DELETE" then
    body = core.request.get_body()                   -- read from the temp file when nginx buffered it there
  end

  local status = lib.ngsildPepDecide(method, ngx.var.uri, ngx.var.args, ngx.var.http_authorization,
                                     ngx.var.http_x_stripped_path, body, body and #body or 0, verdict)
  if status == 0 then
    return
  end

  local title  = ffi.string(verdict.title)
  local detail = ffi.string(verdict.detail)
  if status == 401 then
    core.response.set_header("WWW-Authenticate", ffi.string(verdict.wwwAuthenticate))
  end

  return status, { type = "about:blank", title = title, status = status, detail = (detail ~= "") and detail or title }
end

return _M
