//
// FILE            fdscFetchFile.c
//
// AUTHOR          Ken Zangelin
//
// Copyright 2026 Seamware
// SPDX-License-Identifier: Apache-2.0
//
// fdscFetch for the gateway: a FILE only. fdsc.so's own (fdscFetch.c) also reads a URL with corRest's HTTP
// client - never inside an nginx worker: a blocking read there stalls every request on the worker. The keys
// and the policies are files here; fetching them from the verifier or the PAP is the Lua side's (cosockets).
//
#include <stdio.h>                                   // FILE, fopen, fread, snprintf
#include <string.h>                                  // strncmp

#include "corAlloc/corAlloc.h"                       // corAlloc

#include "fdscFetch.h"                               // Own interface



// -----------------------------------------------------------------------------
//
// fdscFetch - the file's content, NUL-terminated, in kaP; NULL with why in errorBuf
//
char* fdscFetch(const char* where, CorAlloc* kaP, char* errorBuf, int errorBufSize)
{
  if ((strncmp(where, "http://", 7) == 0) || (strncmp(where, "https://", 8) == 0))
  {
    snprintf(errorBuf, errorBufSize, "'%s': a URL - in the gateway the keys and the policies are files", where);
    return NULL;
  }

  FILE* fP = fopen(where, "r");
  if (fP == NULL)
  {
    snprintf(errorBuf, errorBufSize, "cannot open '%s'", where);
    return NULL;
  }

  fseek(fP, 0, SEEK_END);
  long size = ftell(fP);
  fseek(fP, 0, SEEK_SET);

  char* buf = (size >= 0) ? (char*) corAlloc(kaP, size + 1) : NULL;
  if ((buf == NULL) || (fread(buf, 1, size, fP) != (size_t) size))
  {
    fclose(fP);
    snprintf(errorBuf, errorBufSize, "cannot read '%s'", where);
    return NULL;
  }
  fclose(fP);

  buf[size] = 0;
  return buf;
}
