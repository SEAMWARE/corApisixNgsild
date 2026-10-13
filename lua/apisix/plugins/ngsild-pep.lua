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
-- args are fdsc.so's own options (doc/authorization.md § 3.1 in coraine); the keys and the policies are files
-- - nothing below the FFI line does network I/O - or fetched by the plugin, in Lua (cosockets, which do not
-- block nginx), and read by fdsc.so as mem:jwks / mem:policies:
--
--       fetch:
--         discovery: http://verifier:3000/services/data-service/.well-known/openid-configuration   (or jwks: <url>)
--         pap:       http://odrl-pap:8080
--         interval:  30
--       args: [ "--fdscJwks", "mem:jwks", "--fdscPolicies", "mem:policies", "--fdscIssuer", "...", "--fdscRefresh", "2", ... ]
--
-- (--fdscIssuer is then required: fdsc.so reads no discovery document of its own). A route enables it with
-- "ngsild-pep": {}.
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
local http   = require("resty.http")

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
int ngsildPepContentSet(const char* name, const char* text, int len);
]]

local schema = { type = "object", properties = {} }

local attr_schema = {
  type       = "object",
  properties = {
    lib  = { type = "string" },
    args = { type = "array", items = { type = "string" } },
    fetch = {
      type       = "object",
      properties = {
        discovery = { type = "string" },
        jwks      = { type = "string" },
        pap       = { type = "string" },
        interval  = { type = "integer", minimum = 1, default = 30 },
      },
    },
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
local fetchAll                                       -- below

function _M.check_schema(conf)
  return core.schema.check(schema, conf)
end

--
-- fetchAll - the keys (the discovery document's jwks_uri, or jwks) and the policies (every page of the PAP's
-- /policy, as one array) into the C side, as mem:jwks and mem:policies. A fetch that fails keeps what is there
--
local function get(url)
  local c = http.new()
  c:set_timeout(5000)
  local res, err = c:request_uri(url, { method = "GET" })
  if not res then
    return nil, url .. ": " .. tostring(err)
  end
  if res.status ~= 200 then
    return nil, url .. ": " .. res.status
  end
  return res.body
end

fetchAll = function(premature, f)
  if premature or lib == nil then
    return
  end

  local jwksUrl = f.jwks
  if f.discovery ~= nil then
    local d, err = get(f.discovery)
    local doc = d and core.json.decode(d)
    if doc == nil or type(doc.jwks_uri) ~= "string" then
      core.log.warn("ngsild-pep: the discovery document: ", err or "no jwks_uri")
    else
      jwksUrl = doc.jwks_uri
    end
  end
  if jwksUrl ~= nil then
    local b, err = get(jwksUrl)
    if b then
      lib.ngsildPepContentSet("jwks", b, #b)
    else
      core.log.warn("ngsild-pep: the keys: ", err)
    end
  end

  if f.pap ~= nil then
    local all = {}
    for page = 0, 9999 do
      local b, err = get(f.pap .. "/policy?page=" .. page .. "&pageSize=100")
      local items = b and core.json.decode(b)
      if type(items) ~= "table" then
        core.log.warn("ngsild-pep: the policies: ", err or "not a JSON array")
        return
      end
      if #items == 0 then
        break
      end
      for _, it in ipairs(items) do
        all[#all + 1] = it
      end
    end
    local text = (#all > 0) and core.json.encode(all) or "[]"    -- cjson writes an empty table as {}
    lib.ngsildPepContentSet("policies", text, #text)
  end
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

  if attr.fetch ~= nil then
    ngx.timer.at(0, fetchAll, attr.fetch)
    ngx.timer.every(attr.fetch.interval or 30, fetchAll, attr.fetch)
  end
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
