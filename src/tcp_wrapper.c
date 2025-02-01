/*
 * Prime.
 *
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *
 * Copyright (c) 2008 - 2014
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Prime research was provided by the Defense Advanced
 * Research Projects Agency (DARPA) and The National Security Agency (NSA).
 * Prime is not necessarily endorsed by DARPA or the NSA.
 *
 */


#include <stdlib.h>
#include <unistd.h>
#include "tcp_wrapper.h"
#include "spu_alarm.h"

int TCP_Read(int sd, void *dummy_buf, int32u nBytes)
{
  int ret, nRead, nRemaining;
  byte *buf;

  nRemaining = nBytes;
  nRead      = 0;

  buf = (byte *)dummy_buf;

  while(1) {

    ret = read(sd, &buf[nRead], nRemaining);

    if(ret < 0) {
      perror("read");
      Alarm(PRINT, "read returned < 0\n");
      fflush(stdout);
      //exit(0);
      break;
    }
      
    if(ret == 0) {
      Alarm(DEBUG, "read returned 0...\n");
      break;
    }

    if(ret != nBytes)
      Alarm(DEBUG, "Short read in loop: %d out of %d\n", ret, nBytes);

    nRead      += ret;
    nRemaining -= ret;

    if(nRead == nBytes)
      break;
  }

  if(nRead != nBytes) {
    Alarm(DEBUG, "Short read: %d %d\n", nRead, nBytes);
  }

  return ret;
}

int TCP_Write(int sd, void *dummy_buf, int32u nBytes)
{
  int ret, nWritten, nRemaining;
  byte *buf;
  
  buf        = (byte *)dummy_buf;
  nWritten   = 0;
  nRemaining = nBytes;

  while(1) {
    ret = write(sd, &buf[nWritten], nRemaining);
  
    if(ret < 0) {
      perror("write");
      fflush(stdout);
      //exit(0);
      break;
    }

    if(ret == 0) {
      Alarm(DEBUG, "Write returned 0...\n");
      break;
    }

    if(ret != nBytes)
      Alarm(DEBUG, "Short write in loop: %d out of %d\n", ret, nBytes);

    nWritten   += ret;
    nRemaining -= ret;
    
    if(nWritten == nBytes)
      break;
  }

  if(nWritten != nBytes) {
    Alarm(DEBUG, "Short write: %d %d\n", nWritten, nBytes);
  }
  return ret;
}
