/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
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
 *   Amy Babay            babay@cs.jhu.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *      
 * Copyright (c) 2008 - 2017
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "signature.h"
#include "data_structs.h"
#include "openssl_rsa.h"
#include "merkle.h"
#include "process.h"
#include "utility.h"
#include "pre_order.h"
#include "order.h"

extern server_data_struct DATA;
extern server_variables   VAR;
extern network_variables  NET;
extern benchmark_struct   BENCH;

void SIG_Make_Batch(int dummy, void *dummyp);
void SIG_Finish_Pending_Messages(byte *signature);

void SIG_Initialize_Data_Structure()
{
  UTIL_DLL_Initialize(&DATA.SIG.pending_messages_dll);

  /* After adding a message to the pending_messages_dll, how long do
   * we wait before making a batch with whatever we have on the queue
   * (in the hopes of reading more messages and aggregating. This is
   * currently set to a zero timeout -- poll to read as many as we can
   * (up to threshold), then make the signature on the batch.*/
  DATA.SIG.sig_time.sec  = SIG_SEC;
  DATA.SIG.sig_time.usec = SIG_USEC;
					
  DATA.SIG.num_consecutive_messages_read = 0;
}

void SIG_Add_To_Pending_Messages(signed_message *m, int32u dest_bits,
				 int32u timeliness)
{
  sp_time t;

  UTIL_DLL_Add_Data(&DATA.SIG.pending_messages_dll, m);
  UTIL_DLL_Set_Last_Extra(&DATA.SIG.pending_messages_dll, DEST, dest_bits);
  UTIL_DLL_Set_Last_Extra(&DATA.SIG.pending_messages_dll, TIMELINESS,
			  timeliness);

  if(DATA.SIG.pending_messages_dll.length == SIG_THRESHOLD)
    SIG_Make_Batch(0, NULL);
  else {
    if (DATA.VIEW.view_change_done == 0) {
        t = DATA.SIG.sig_time;
        t.usec /= 4;
        E_queue(SIG_Make_Batch, 0, NULL, t);
    }
    else
        E_queue(SIG_Make_Batch, 0, NULL, DATA.SIG.sig_time);
  }
}

void SIG_Make_Batch(int dummy, void *dummyp)
{
  byte signature[SIGNATURE_SIZE];
  byte *proot = NULL;
  
  /* If there's nothing to do, we're done. */
  if(UTIL_DLL_Is_Empty(&DATA.SIG.pending_messages_dll))
    return;

#if 0
  Alarm(PRINT, "Signing %d messages, %f\n", 
	DATA.SIG.pending_messages_dll.length,
	UTIL_DLL_Elapsed_Front(&DATA.SIG.pending_messages_dll));
#endif

  /* Build the root digest out of the list of pending messages, and then
   * generate a signature on the root digest. */
  proot = MT_Make_Digest_From_List(&DATA.SIG.pending_messages_dll);

  /* Sign the root digest */
  memset(signature, 0, SIGNATURE_SIZE);
  OPENSSL_RSA_Make_Signature(proot, signature);
  
  BENCH.num_signatures++;
  BENCH.total_signed_messages += DATA.SIG.pending_messages_dll.length;
  if(DATA.SIG.pending_messages_dll.length > BENCH.max_signature_batch_size) {
    BENCH.max_signature_batch_size = 
      DATA.SIG.pending_messages_dll.length;
  }

  SIG_Finish_Pending_Messages(signature);
}

void SIG_Attempt_To_Generate_PO_Messages()
{
  if(SEND_PO_REQUESTS_PERIODICALLY)
    PRE_ORDER_Send_PO_Request();

  if(SEND_PO_ACKS_PERIODICALLY)
    PRE_ORDER_Send_PO_Ack();

  if(SEND_PO_ARU_PERIODICALLY)
    PRE_ORDER_Send_PO_ARU();

  if(!UTIL_I_Am_Leader())
    PRE_ORDER_Send_Proof_Matrix();
}

void SIG_Finish_Pending_Messages(byte *signature)
{
  signed_message *mess;
  dll_struct *list;
  dll_struct original_list;
  int32u sn, i, dest_bits, timeliness;

  list = &DATA.SIG.pending_messages_dll;
  sn   = list->length;
  MT_Set_Num(sn);

  UTIL_DLL_Initialize(&original_list);
  UTIL_DLL_Set_Begin(list);
  i = 1;
  
  while((mess = (signed_message *)UTIL_DLL_Front_Message(list)) != NULL) {
    
    assert(mess);
    dest_bits  = UTIL_DLL_Front_Extra(list, DEST);
    timeliness = UTIL_DLL_Front_Extra(list, TIMELINESS);

    /* Copy the signature into the message. */
    memcpy((byte*)mess, signature, SIGNATURE_SIZE);
    
    /* Generate the digests and stick them into the message */
    MT_Extract_Set(i, mess);
    if(mess->mt_index > mess->mt_num) {
      Alarm(PRINT, "sn = %d, i = %d, index = %d, mt_num = %d\n", 
	    sn, i, mess->mt_index, mess->mt_num);
      assert(0);
    }
    i++;

    /* Add it to the original list.  Keep track of this because applying
     * may cause new messages to be added to the pending_local_messages_dll. */
    UTIL_DLL_Add_Data(&original_list, mess);    
    UTIL_DLL_Set_Last_Extra(&original_list, DEST, dest_bits);
    UTIL_DLL_Set_Last_Extra(&original_list, TIMELINESS, timeliness);

    UTIL_DLL_Pop_Front(list);
  }

  UTIL_DLL_Set_Begin(&original_list);
  while((mess = (signed_message *)UTIL_DLL_Front_Message(&original_list)) 
	!= NULL) {

    assert(mess->type != UPDATE);
    BENCH.signature_types[mess->type]++;

    dest_bits  = UTIL_DLL_Front_Extra(&original_list, DEST);
    timeliness = UTIL_DLL_Front_Extra(&original_list, TIMELINESS);
    
    /* Once signed, client responses should be sent to the client */
    if(mess->type == CLIENT_RESPONSE)
      UTIL_Write_Client_Response(mess);   
    else {

      /* Apply the message and then dispatch it, just as we would a local
       * message that we constructed, unless it's a RECON message. */
      //if(mess->type != RECON) {
      if (dest_bits == BROADCAST) {
	    PROCESS_Message(mess);
      }
      
      /* If we're throttling outgoing messages, add it to the appropriate
       * queue based on timeliness. Otherwise, send immediately to the 
       * appropriate destination. */
#if THROTTLE_OUTGOING_MESSAGES
      NET_Add_To_Pending_Messages(mess, dest_bits, timeliness);
#else
  #if 0
      /* Send the proof matrix to the leader, send recon messages to only
       * those that need it.  Everything else broadcast. */
      if(mess->type == PROOF_MATRIX || mess->type == RECON) {
	for(i = 1; i <= NUM_SERVERS; i++) {
	  if(UTIL_Bitmap_Is_Set(&dest_bits, i))
	    UTIL_Send_To_Server(mess, i);
	}
      }
      /* Delay attack: leader only sends Pre-Prepare to server 2 */
      else if(DELAY_ATTACK && UTIL_I_Am_Leader() && mess->type == PRE_PREPARE)
	UTIL_Send_To_Server(mess, 2);
      
      /* Recon attack: Faulty servers don't send to top f correct servers */
      else if (UTIL_I_Am_Faulty() && mess->type == PO_REQUEST) {
	for(i = 1; i <= NUM_SERVERS; i++) {
	  if( (i <= (2*NUM_F + NUM_K + 1)) && (i != VAR.My_Server_ID) )
	    UTIL_Send_To_Server(mess, i);
	}
      }
      else
	UTIL_Broadcast(mess);
  #endif
      /* Delay attack: leader only sends Pre-Prepare to server 2 */
      if(DELAY_ATTACK && UTIL_I_Am_Leader() && mess->type == PRE_PREPARE)
	    UTIL_Send_To_Server(mess, 2);
      
      /* Recon attack: Faulty servers don't send to top f correct servers */
      else if (UTIL_I_Am_Faulty() && mess->type == PO_REQUEST) {
	    for(i = 1; i <= NUM_SERVERS; i++) {
	      if( (i <= (2*NUM_F + NUM_K + 1)) && (i != VAR.My_Server_ID) )
	        UTIL_Send_To_Server(mess, i);
	    }
      }
      /* Send non-broadcast messages to specific server that needs it,
       * e.g., proof matrix and recon messages. */
      else if (dest_bits != BROADCAST) {
	    for(i = 1; i <= NUM_SERVERS; i++) {
	      if(UTIL_Bitmap_Is_Set(&dest_bits, i))
	        UTIL_Send_To_Server(mess, i);
	    }
      }
      /* Otherwise, its a broadcast message */
      else {
        //if (mess->type != REPLAY_COMMIT)
	      UTIL_Broadcast(mess);
      }
#endif
    } 
    
    /* Always pop */
    UTIL_DLL_Pop_Front(&original_list);
  }
  assert(UTIL_DLL_Is_Empty(&original_list));
}
