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
 * The Creators of Prime are:
 *  Yair Amir, Jonathan Kirsch, and John Lane.
 *
 * Special thanks to Brian Coan for major contributions to the design of
 * the Prime algorithm. 
 *  	
 * Copyright (c) 2008 - 2013 
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *     Jeff Seibert
 *
 */

#include <string.h>
#include <stdlib.h>
#include "util/arch.h"
#include "util/alarm.h"
#include "util/sp_events.h"
#include "util/memory.h"
#include "util/data_link.h"
#include "net_types.h"
#include "objects.h"
#include "network.h"
#include "data_structs.h"
#include "utility.h"
#include "error_wrapper.h"
#include "recon.h"

/* Externally defined global variables */
extern server_variables  VAR;
extern network_variables NET;

/* Local Function Definitions */
void Usage(int argc, char **argv);
void Print_Usage(void);
void Init_Memory_Objects(void);

int main(int argc, char** argv) 
{ 
  Usage(argc, argv);
  Alarm_set(NONE);

  /* This is the server program */
  NET.program_type = NET_SERVER_PROGRAM_TYPE;  
  
  Alarm(PRINT,"Running Server %d\n", VAR.My_Server_ID);
  
  /* Load server addresses from configuration file */
  UTIL_Load_Addresses(); 
  
  ERROR_WRAPPER_Initialize(); 

  E_init(); 
  Init_Memory_Objects();
  Init_Network();
  
  /* Initialize RSA Keys */
  OPENSSL_RSA_Init();
  OPENSSL_RSA_Read_Keys(VAR.My_Server_ID, RSA_SERVER); 
  TC_Read_Public_Key();
  TC_Read_Partial_Key(VAR.My_Server_ID, 1);//no multi-site, so just "1"

  Alarm(PRINT, "Finished reading keys.\n");

  /* Initialize this server's data structures */
  DAT_Initialize();  

  /* Start the server's main event loop */
  E_handle_events();

  return 0;
}

void Init_Memory_Objects(void)
{
  /* Initilize memory object types  */
  Mem_init_object_abort(PACK_BODY_OBJ,    sizeof(packet),           100,  1);
  Mem_init_object_abort(SYS_SCATTER,      sizeof(sys_scatter),      100,  1);
  Mem_init_object_abort(DLL_NODE_OBJ,     sizeof(dll_node_struct),  200, 20);
  Mem_init_object_abort(PO_SLOT_OBJ,      sizeof(po_slot),          200, 20);
  Mem_init_object_abort(ORD_SLOT_OBJ,     sizeof(ord_slot),         200, 20);
  Mem_init_object_abort(ERASURE_NODE_OBJ, sizeof(erasure_node),     200, 20);
  Mem_init_object_abort(ERASURE_PART_OBJ, sizeof(erasure_part_obj), 200, 20);
  Mem_init_object_abort(RECON_SLOT_OBJ,   sizeof(recon_slot),       200, 20);
  Mem_init_object_abort(NET_STRUCT_OBJ,   sizeof(net_struct),       200, 20);
}

void Usage(int argc, char **argv)
{
  int tmp;

  if(NUM_SERVERS < (3*NUM_FAULTS+1)) {
    Alarm(PRINT, "Configuration error: NUM_SERVERS must be at least 3f+1\n");
    exit(0);
  }

  VAR.Faults               = NUM_FAULTS;
  VAR.My_Server_ID         = 1;

  while(--argc > 0) {
    argv++;

    /* [-i server_id] */
    if( (argc > 1) && (!strncmp(*argv, "-i", 2)) ) {
      sscanf(argv[1], "%d", &tmp);
      VAR.My_Server_ID = tmp;
      if(VAR.My_Server_ID > NUM_SERVERS || VAR.My_Server_ID <= 0) {
	Alarm(PRINT,"Invalid server id: %d.  Index must be between 1 and %d.\n",
	      VAR.My_Server_ID, NUM_SERVERS);
	exit(0);
      }
      argc--; argv++;
    }
    else
      Print_Usage();
  }
}

void Print_Usage()
{
  Alarm(PRINT, "Usage: ./server\n"
	"\t[-i local_id, indexed base 1, default 1]\n");
  exit(0);
}
