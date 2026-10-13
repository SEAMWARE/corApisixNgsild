//
// FILE            fdscFetchFile.c
//
// AUTHOR          Ken Zangelin
//
// Copyright 2026 Seamware
// SPDX-License-Identifier: Apache-2.0
//
// fdscFetch for the gateway: a FILE, or "mem:<name>" - a content the plugin's Lua side fetched (from the
// verifier, the PAP: cosockets, which do not block nginx) and handed over with ngsildPepContentSet. fdsc.so's
// own (fdscFetch.c) reads a URL with corRest's HTTP client - never inside an nginx worker: a blocking read
// there stalls every request on the worker.
//
#include <pthread.h>                                 // pthread_mutex_t
#include <stdio.h>                                   // FILE, fopen, fread, snprintf
#include <stdlib.h>                                  // malloc, free
#include <string.h>                                  // strncmp, strcmp, memcpy

#include "corAlloc/corAlloc.h"                       // corAlloc

#include "fdscFetch.h"                               // Own interface



// -----------------------------------------------------------------------------
//
// The contents handed over - a few, by name ("jwks", "policies"), each replaced whole
//
typedef struct Content
{
  char   name[32];
  char*  text;
  int    len;
} Content;

static Content          contentV[8];
static pthread_mutex_t  contentMutex = PTHREAD_MUTEX_INITIALIZER;



// -----------------------------------------------------------------------------
//
// fdscFetchContentSet - a content by name, copied; 0, or -1 (no room, no memory)
//
int fdscFetchContentSet(const char* name, const char* text, int len)
{
  char* copy = (char*) malloc(len + 1);
  if ((copy == NULL) || (strlen(name) >= sizeof(contentV[0].name)))
  {
    free(copy);
    return -1;
  }
  memcpy(copy, text, len);
  copy[len] = 0;

  pthread_mutex_lock(&contentMutex);

  Content* cP = NULL;
  for (int ix = 0; ix < (int) (sizeof(contentV) / sizeof(contentV[0])); ix++)
  {
    if (strcmp(contentV[ix].name, name) == 0)  { cP = &contentV[ix]; break; }
    if ((cP == NULL) && (contentV[ix].name[0] == 0))  cP = &contentV[ix];
  }

  if (cP == NULL)
  {
    pthread_mutex_unlock(&contentMutex);
    free(copy);
    return -1;
  }

  free(cP->text);
  snprintf(cP->name, sizeof(cP->name), "%s", name);
  cP->text = copy;
  cP->len  = len;

  pthread_mutex_unlock(&contentMutex);
  return 0;
}



// -----------------------------------------------------------------------------
//
// contentGet - a copy of the content in kaP; NULL with why in errorBuf
//
static char* contentGet(const char* name, CorAlloc* kaP, char* errorBuf, int errorBufSize)
{
  char* text = NULL;

  pthread_mutex_lock(&contentMutex);
  for (int ix = 0; ix < (int) (sizeof(contentV) / sizeof(contentV[0])); ix++)
  {
    if ((contentV[ix].text != NULL) && (strcmp(contentV[ix].name, name) == 0))
    {
      text = (char*) corAlloc(kaP, contentV[ix].len + 1);
      if (text != NULL)
        memcpy(text, contentV[ix].text, contentV[ix].len + 1);
      break;
    }
  }
  pthread_mutex_unlock(&contentMutex);

  if (text == NULL)
    snprintf(errorBuf, errorBufSize, "'mem:%s': not fetched yet", name);

  return text;
}



// -----------------------------------------------------------------------------
//
// fdscFetch - the file's content (or mem:<name>'s), NUL-terminated, in kaP; NULL with why in errorBuf
//
char* fdscFetch(const char* where, CorAlloc* kaP, char* errorBuf, int errorBufSize)
{
  if (strncmp(where, "mem:", 4) == 0)
    return contentGet(&where[4], kaP, errorBuf, errorBufSize);

  if ((strncmp(where, "http://", 7) == 0) || (strncmp(where, "https://", 8) == 0))
  {
    snprintf(errorBuf, errorBufSize, "'%s': a URL - in the gateway: a file, or mem:<name> (the plugin's fetch)", where);
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
