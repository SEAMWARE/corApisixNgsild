//
// FILE            ngsildPep.c
//
// AUTHOR          Ken Zangelin
//
// Copyright 2026 Seamware
// SPDX-License-Identifier: Apache-2.0
//
// The decision of the APISIX plugin: fdsc.so's own code - the token checked and the ODRL policies decided as
// coraine's --auth fdsc does, compiled from its sources unchanged - behind two functions for LuaJIT's FFI:
//
//   ngsildPepInit(argc, argv, errorBuf, errorBufSize)          fdsc.so's options (--fdscJwks <file> ...)
//   ngsildPepDecide(method, path, query, authorization, strippedPath, body, bodyLen, verdictP)
//
// One call is one whole decision and does no I/O: nginx runs many requests on one thread, and a call that
// blocked would stall every one of them. fdsc.so's refresh thread reads the keys and the policies from their
// files (fdscFetchFile.c), never from the network.
//
#include <stdbool.h>                                 // bool
#include <stdint.h>                                  // intptr_t
#include <stdio.h>                                   // snprintf
#include <stdlib.h>                                  // malloc, free
#include <string.h>                                  // strcmp, strcasecmp, strlen, memcpy
#include <strings.h>                                 // strcasecmp

#include "corArgs/CorArg.h"                          // CorArg
#include "corLog/corLogInit.h"                       // corLogInit
#include "plugin/AuthDriver.h"                       // AuthDriver, AuthRequest, AuthAnswer, AuthVerdict



// -----------------------------------------------------------------------------
//
// NgsildPepVerdict - what the plugin answers: status 0 lets the request through
//
typedef struct NgsildPepVerdict
{
  int   status;                                      // 0: let through; 401, 403, 503
  char  title[128];
  char  detail[1024];
  char  wwwAuthenticate[512];
} NgsildPepVerdict;

extern void authRegister(AuthDriver* driverP);       // fdsc.c
extern int  fdscFetchContentSet(const char* name, const char* text, int len);   // fdscFetchFile.c

static AuthDriver  driver;
static bool        initDone = false;



// -----------------------------------------------------------------------------
//
// The request of the call - read by the AuthRequest callbacks; one call at a time (one nginx thread)
//
static const char*  reqAuthorization;
static const char*  reqStrippedPath;
static const char*  reqBody;
static int          reqBodyLen;

static const char* header(const char* name)
{
  if (strcasecmp(name, "Authorization") == 0)    return reqAuthorization;
  if (strcasecmp(name, "x-stripped-path") == 0)  return reqStrippedPath;
  return NULL;
}

static const char* body(int* lenP)
{
  if (lenP != NULL)
    *lenP = (reqBody != NULL) ? reqBodyLen : 0;
  return reqBody;
}

static const char* expandAsIs(const char* term)
{
  return term;                                       // the connector's decisions never expand (fdsc.so without --fdscNgsild)
}



// -----------------------------------------------------------------------------
//
// argSet - one of fdsc.so's options, as corArgs would set it
//
static bool argSet(CorArg* aP, const char* value, char* errorBuf, int errorBufSize)
{
  switch (aP->type)
  {
  case CorArgString:  *((char**) aP->valueP) = (value != NULL) ? strdup(value) : NULL; return true;
  case CorArgInt:     *((int*)   aP->valueP) = (value != NULL) ? atoi(value) : (int) (intptr_t) aP->def; return true;
  case CorArgBool:    *((bool*)  aP->valueP) = (value != NULL) ? true : (bool) (intptr_t) aP->def; return true;
  default:
    snprintf(errorBuf, errorBufSize, "%s: an option of a type the gateway does not set", aP->longName);
    return false;
  }
}



// -----------------------------------------------------------------------------
//
// ngsildPepInit - fdsc.so registered and initialised with these options; 0, or -1 with why in errorBuf
//
// argv: "--fdscJwks", "/etc/keys.json", "--fdscPolicies", "/etc/policies.json", "--fdscIssuer", "http://v", ...
// A boolean option takes no value ("--fdscNgsild"). An option fdsc.so does not have is refused.
//
__attribute__((visibility("default"))) int ngsildPepInit(int argc, const char** argv, char* errorBuf, int errorBufSize)
{
  if (initDone == true)
  {
    snprintf(errorBuf, errorBufSize, "already initialised");
    return -1;
  }

  //
  // --fdscNgsild decides on each entity a request reads or writes - its stored types, attributes and tenant,
  // which the broker has and the gateway does not. Refused, not half done
  //
  for (int ix = 0; ix < argc; ix++)
  {
    if (strcmp(argv[ix], "--fdscNgsild") == 0)
    {
      snprintf(errorBuf, errorBufSize, "--fdscNgsild decides on each stored entity - a gateway does not have them: "
               "coraine's --auth fdsc --fdscNgsild does it in the broker");
      return -1;
    }
  }

  memset(&driver, 0, sizeof(driver));
  driver.abiVersion = AUTH_ABI_VERSION;
  authRegister(&driver);

  //
  // The defaults first - corArgs sets each option to its default before the command line
  //
  for (CorArg* aP = driver.args; (aP != NULL) && (aP->type != CorArgEnd); ++aP)   // CORARGS_END: type CorArgEnd, name ""
  {
    if (aP->type == CorArgString)
      *((char**) aP->valueP) = (char*) aP->def;
    else if (argSet(aP, NULL, errorBuf, errorBufSize) == false)
      return -1;
  }

  for (int ix = 0; ix < argc; ix++)
  {
    CorArg* aP = driver.args;
    while ((aP->type != CorArgEnd) && (strcmp(aP->longName, argv[ix]) != 0))
      ++aP;

    if (aP->type == CorArgEnd)
    {
      snprintf(errorBuf, errorBufSize, "unknown option: %s", argv[ix]);
      return -1;
    }

    const char* value = NULL;
    if (aP->type != CorArgBool)
    {
      if (ix + 1 >= argc)
      {
        snprintf(errorBuf, errorBufSize, "%s needs a value", argv[ix]);
        return -1;
      }
      value = argv[++ix];
    }
    else
      value = "";

    if (argSet(aP, value, errorBuf, errorBufSize) == false)
      return -1;
  }

  if (driver.init(errorBuf, errorBufSize) == false)
    return -1;

  initDone = true;
  return 0;
}



// -----------------------------------------------------------------------------
//
// paramsSplit - the query string as the broker gets it: name=value pairs, decoded ('+' a space, %XX a byte)
//
static int decode(char* s)
{
  char* to = s;

  for (char* from = s; *from != 0; ++from)
  {
    if (*from == '+')
      *to++ = ' ';
    else if ((from[0] == '%') && (from[1] != 0) && (from[2] != 0))
    {
      char hex[3] = { from[1], from[2], 0 };
      char* end;
      long  v = strtol(hex, &end, 16);
      if (*end == 0) { *to++ = (char) v; from += 2; }
      else           *to++ = *from;
    }
    else
      *to++ = *from;
  }
  *to = 0;
  return 0;
}

static int paramsSplit(char* query, const char** keyV, const char** valueV, int max)
{
  int n = 0;

  for (char* p = query; (p != NULL) && (*p != 0) && (n < max); )
  {
    char* amp = strchr(p, '&');
    if (amp != NULL)
      *amp = 0;

    if (*p != 0)
    {
      char* eq = strchr(p, '=');
      if (eq != NULL) *eq = 0;
      decode(p);
      if (eq != NULL) decode(eq + 1);
      keyV[n]   = p;
      valueV[n] = (eq != NULL) ? eq + 1 : "";
      n++;
    }
    p = (amp != NULL) ? amp + 1 : NULL;
  }

  return n;
}



// -----------------------------------------------------------------------------
//
// verdictSet -
//
static int verdictSet(NgsildPepVerdict* vP, AuthVerdict v, const AuthAnswer* aP)
{
  static const int status[] = { 0, 401, 403, 503 };
  static const char* title[] = { "", "Unauthorized", "Forbidden", "Service Unavailable" };

  vP->status = ((int) v >= 0 && (int) v <= 3) ? status[v] : 503;
  snprintf(vP->title,  sizeof(vP->title),  "%s", ((aP->title != NULL) ? aP->title : title[((int) v >= 0 && (int) v <= 3) ? v : 3]));
  snprintf(vP->detail, sizeof(vP->detail), "%s", (aP->detail != NULL) ? aP->detail : "");
  snprintf(vP->wwwAuthenticate, sizeof(vP->wwwAuthenticate), "%s", (aP->wwwAuthenticate != NULL) ? aP->wwwAuthenticate : ((v == AuthUnauthenticated) ? "Bearer" : ""));
  return vP->status;
}



// -----------------------------------------------------------------------------
//
// ngsildPepDecide - may this request through: the verdict's status (0: let through)
//
// path: the URL path, decoded, without the query; query: the raw query string (NULL: none); body: as the
// client sent it (NULL: none). What the broker hands fdsc.so, for a request the gateway forwards.
//
__attribute__((visibility("default"))) int ngsildPepDecide
(
  const char*        method,
  const char*        path,
  const char*        query,
  const char*        authorization,
  const char*        strippedPath,
  const char*        bodyP,
  int                bodyLen,
  NgsildPepVerdict*  vP
)
{
  AuthAnswer answer = { NULL, NULL, NULL, false };

  memset(vP, 0, sizeof(*vP));
  if (initDone == false)
  {
    answer.detail = "the gateway's NGSI-LD plugin is not initialised";
    return verdictSet(vP, AuthUnavailable, &answer);
  }

  //
  // The query - decoded in a copy
  //
  const char* keyV[128];
  const char* valueV[128];
  int         params = 0;
  char        qbuf[8192];
  char*       qcopy  = NULL;

  if ((query != NULL) && (*query != 0))
  {
    size_t len = strlen(query);
    qcopy = (len < sizeof(qbuf)) ? qbuf : (char*) malloc(len + 1);
    if (qcopy == NULL)
    {
      answer.detail = "no memory for the query";
      return verdictSet(vP, AuthUnavailable, &answer);
    }
    memcpy(qcopy, query, len + 1);
    params = paramsSplit(qcopy, keyV, valueV, 128);
  }

  reqAuthorization = authorization;
  reqStrippedPath  = strippedPath;
  reqBody          = bodyP;
  reqBodyLen       = bodyLen;

  AuthRequest req;
  memset(&req, 0, sizeof(req));
  req.method        = method;
  req.path          = path;
  req.params        = params;
  req.paramKeyV     = keyV;
  req.paramValueV   = valueV;
  req.header        = header;
  req.body          = body;
  req.expand        = NULL;                           // decided before any @context, as fdsc.so is in the broker (ABI 3)
  req.expandDefault = expandAsIs;
  req.entities      = false;

  void*       identity = NULL;
  AuthVerdict v        = driver.authenticate(&req, &identity, &answer);

  if ((v == AuthAllow) && (driver.authorize != NULL))
    v = driver.authorize(&req, identity, &answer);

  verdictSet(vP, v, &answer);

  if ((identity != NULL) && (driver.release != NULL))
    driver.release(identity);

  if ((qcopy != NULL) && (qcopy != qbuf))
    free(qcopy);

  reqAuthorization = NULL;
  reqStrippedPath  = NULL;
  reqBody          = NULL;
  return vP->status;
}



// -----------------------------------------------------------------------------
//
// ngsildPepLogInit - fdsc.so's log lines (W:, I:, E:, X:) to the process's stdout - in the APISIX container,
// the container's log, beside nginx's; level ERR, WARN (the default), INFO, VERBOSE. 0, or -1 (corLog's)
//
__attribute__((visibility("default"))) int ngsildPepLogInit(const char* level)
{
  return (corLogInit("ngsild-pep", NULL, true, (level != NULL) ? level : "WARN", NULL, false, false) == 0) ? 0 : -1;
}



// -----------------------------------------------------------------------------
//
// ngsildPepContentSet - a content the Lua side fetched, read by fdsc.so as "mem:<name>" (--fdscJwks mem:jwks,
// --fdscPolicies mem:policies) at its next refresh; 0, or -1
//
__attribute__((visibility("default"))) int ngsildPepContentSet(const char* name, const char* text, int len)
{
  return fdscFetchContentSet(name, text, len);
}
