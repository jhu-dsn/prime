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
 * Copyright (c) 2008 - 2010 
 * The Johns Hopkins University.
 * All rights reserved.
 *
 */

#include <string.h>
#include <assert.h>
#include "util/alarm.h"
#include "util/memory.h"
#include "packets.h"
#include "utility.h"
#include "data_structs.h"
#include "merkle.h"
#include "validate.h"
#include "recon.h"

extern server_data_struct DATA; 
extern server_variables   VAR;
extern benchmark_struct   BENCH;

signed_message* PRE_ORDER_Construct_PO_Request()
{
  signed_message *po_request;
  po_request_message *po_request_specific;
  int32u bytes, this_mess_len, num_events, wa_bytes, cutoff;
  signed_message *mess;
  char *p;

  /* Construct new message */
  po_request          = UTIL_New_Signed_Message();
  po_request_specific = (po_request_message *)(po_request + 1);

  /* Fill in the message based on the event. We construct a message
   * that contains the event by copying the event (which may or may
   * not be a signed message) into the PO Request message. */
  
  po_request->machine_id       = VAR.My_Server_ID;
  po_request->type             = PO_REQUEST;
  po_request_specific->seq_num = DATA.PO.po_seq_num++;

  /* We'll be adding to at least this many bytes */
  bytes = sizeof(signed_message) + sizeof(po_request_message);
  
  num_events = 0;

  /* When we copy, we'll be starting right after the PO request */
  p = (char *)(po_request_specific+1);
  
  cutoff = PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS);

  while(bytes < cutoff) {

    wa_bytes = 0;

    /* If there are no more messages, stop. Otherwise grab one and see
     * if it will fit. */
    if((mess = UTIL_DLL_Front_Message(&DATA.PO.po_request_dll)) == NULL)
      break;

    this_mess_len = mess->len + sizeof(signed_message) + wa_bytes;

    if((bytes + this_mess_len) < cutoff) {
      num_events++;
      bytes += this_mess_len;

      /* Copy it into the packet */
      memcpy(p, mess, this_mess_len);
      p += this_mess_len;

      UTIL_DLL_Pop_Front(&DATA.PO.po_request_dll);
    }
    else {
      Alarm(DEBUG, "Won't fit: this_mess_len = %d, type = %d, wa = %d\n", 
	    this_mess_len, mess->type, wa_bytes);
      break;
    }
  }

  
  po_request_specific->num_events = num_events;
  /* Subtract sizeof(signed_message) because even though we send out
   * that many bytes, the len field is just the content, not the signed
   * message part. */
  po_request->len = bytes - sizeof(signed_message);
  
  BENCH.num_po_requests_sent++;
  BENCH.total_updates_requested += num_events;

  return po_request;
}

signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack)
{
  signed_message *po_ack;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part;
  int32u nparts;
  int32u sm, i;
  po_slot *slot;
  int32u po_request_len;

  /* Construct new message */
  po_ack          = UTIL_New_Signed_Message();
  po_ack_specific = (po_ack_message*)(po_ack + 1);
  
  po_ack->machine_id = VAR.My_Server_ID;
  po_ack->type       = PO_ACK;
  
  /* we must ack all of the unacked po request messages, received
   * contiguously */
  
  ack_part = (po_ack_part*)(po_ack_specific+1);
  
  nparts     = 0;
  
  for(sm = 1; sm <= NUM_SERVERS; sm++) {
    
    assert(DATA.PO.max_acked[sm] <= DATA.PO.aru[sm]);
    
    for(i = DATA.PO.max_acked[sm]+1; i <= DATA.PO.aru[sm]; i++) {
      DATA.PO.max_acked[sm] = i;
      slot = UTIL_Get_PO_Slot_If_Exists(sm, i);
      
      if(slot == NULL) {
	/* We received a PO-Request but decided not to ack yet due to 
	 * aggregation.  Then we order the PO-Request using acks from 
	 * the other servers.  Now we're ready to send the ack but we've
	 * already garbage collected!  This is ok.  Just pretend like
	 * we're acking; everyone else will execute eventually. */
	Alarm(DEBUG, "Continuing locally on %d %d\n", sm, i);
	assert(DATA.PO.white_line[sm] >= i);
	continue;
      }
  
#if RECON_ATTACK
      /* Faulty servers don't ack anyone else's stuff */
      if (UTIL_I_Am_Faulty() && sm > NUM_FAULTS)
	continue;
#endif

      /* Create the ack_part */
      ack_part[nparts].originator = sm;
      ack_part[nparts].seq_num    = i;
      
      /* Modified this.  Includes possible appended digest bytes and
       * does not subtract the signature_size. */
      po_request_len = (sizeof(signed_message) + slot->po_request->len +
			MT_Digests_(slot->po_request->mt_num) * DIGEST_SIZE);

      /* Now compute the digest of the event and copy it into the
       * digest field */
      OPENSSL_RSA_Make_Digest((byte *)(slot->po_request), po_request_len,
			      ack_part[nparts].digest);      
      nparts++;

      if(nparts == MAX_ACK_PARTS)
	goto finish;
    }
  }
  
 finish:

  po_ack_specific->num_ack_parts = nparts;
  
  if (nparts == 0) {
    /* There is nothing in the ack -- we will not send it */
    *more_to_ack = 0;
    dec_ref_cnt( po_ack );
    return NULL;
  }

  if (nparts > MAX_ACK_PARTS) { 
    Alarm(EXIT,"%d BIG LOCAL ACK nparts = %d\n", VAR.My_Server_ID, nparts); 
  }

  po_ack->len = (sizeof(po_ack_message) + 
		 sizeof(po_ack_part) * po_ack_specific->num_ack_parts);
  
  if(nparts == MAX_ACK_PARTS) {
    Alarm(DEBUG, "There may be more to ack!\n");
    *more_to_ack = 1;
  }
  else {
    *more_to_ack = 0;
    Alarm(DEBUG, "Acked %d parts\n", nparts);
  }
  
  BENCH.num_po_acks_sent++;
  BENCH.num_acks += nparts;

  return po_ack;
}

signed_message* PRE_ORDER_Construct_PO_ARU()
{
  int32u s;
  signed_message *po_aru;
  po_aru_message *po_aru_specific;

  /* Construct new message */
  po_aru          = UTIL_New_Signed_Message();
  po_aru_specific = (po_aru_message*)(po_aru + 1);

  po_aru->machine_id = VAR.My_Server_ID;
  po_aru->type       = PO_ARU;
  po_aru->len        = sizeof(po_aru_message);
  
  po_aru_specific->num = DATA.PO.po_aru_num;
  DATA.PO.po_aru_num++;

  /* Fill in vector of cumulative pre order acks */
  for (s = 0; s < NUM_SERVERS; s++)
    po_aru_specific->ack_for_server[s] = DATA.PO.cum_aru[s+1];

#if 0
  /* Compute a standard RSA signature. */
  Alarm(PRINT, "Signature: Local PO-ARU\n");
  UTIL_RSA_Sign_Message(po_aru);
#endif  

  return po_aru;
}

void PRE_ORDER_Construct_Proof_Matrix(signed_message **mset,
				      int32u *num_parts)
{
  signed_message *mess;
  proof_matrix_message *pm_specific;
  int32u total_parts, i, index, length;

  /* TODO: MAKE THIS GENERIC FOR ANY f */
  if(NUM_FAULTS == 1)
    total_parts = 1;
  else
    total_parts = 2;
  
  for(i = 1; i <= total_parts; i++) {
    mset[i] = UTIL_New_Signed_Message();
    mess    = (signed_message *)mset[i];

    mess->type       = PROOF_MATRIX;
    mess->machine_id = VAR.My_Server_ID;
    mess->len        = 0; /* Set below */

    pm_specific      = (proof_matrix_message *)(mess+1);

    if(NUM_FAULTS == 1)
      pm_specific->num_acks_in_this_message = 4;
    else {
      if(i == 1)
	pm_specific->num_acks_in_this_message = (3*NUM_FAULTS+1) / 2;
      else
	pm_specific->num_acks_in_this_message = ((3*NUM_FAULTS+1) - 
						 ((3*NUM_FAULTS+1)/2));
    }
  }

  index = 1;
  for(i = 1; i <= total_parts; i++) {
    pm_specific = (proof_matrix_message *)(mset[i] + 1);
    length      = (sizeof(po_aru_signed_message) * 
		   pm_specific->num_acks_in_this_message);
    
    memcpy((byte *)(pm_specific + 1), (byte *)(DATA.PO.cum_acks+index),
	 length);
    mset[i]->len = sizeof(proof_matrix_message) + length;
    index += pm_specific->num_acks_in_this_message;
  }

  *num_parts = total_parts;
}

void ORDER_Construct_Pre_Prepare(signed_message **mset,int32u *num_parts)
{
  signed_message *mess;
  pre_prepare_message *pp_specific;
  int32u total_parts, i, index, length;

  /* TODO: MAKE THIS GENERIC FOR ANY f */
  if(NUM_FAULTS == 1)
    total_parts = 1;
  else
    total_parts = 2;

  for(i = 1; i <= total_parts; i++) {
    mset[i] = UTIL_New_Signed_Message();
    mess    = (signed_message *)mset[i];

    mess->type       = PRE_PREPARE;
    mess->machine_id = VAR.My_Server_ID;
    mess->len        = 0; /* Set below */

    pp_specific              = (pre_prepare_message *)(mess+1);
    pp_specific->seq_num     = DATA.ORD.seq;
    pp_specific->view        = DATA.View;
    pp_specific->part_num    = i;
    pp_specific->total_parts = total_parts;

    if(NUM_FAULTS == 1)
      pp_specific->num_acks_in_this_message = 4;
    else {
      if(i == 1)
	pp_specific->num_acks_in_this_message = (3*NUM_FAULTS+1) / 2;
      else
	pp_specific->num_acks_in_this_message = ((3*NUM_FAULTS+1) - 
						 ((3*NUM_FAULTS+1)/2));
    }
  }
  
  index = 1;
  for(i = 1; i <= total_parts; i++) {
    pp_specific = (pre_prepare_message *)(mset[i] + 1);
    length      = (sizeof(po_aru_signed_message) * 
		   pp_specific->num_acks_in_this_message);

    memcpy((byte *)(pp_specific + 1), (byte *)(DATA.PO.cum_acks+index),
	   length);
    mset[i]->len = sizeof(pre_prepare_message) + length;
    index += pp_specific->num_acks_in_this_message;
  }
  
  DATA.ORD.seq++;
  *num_parts = total_parts;
}

signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp)
{
  signed_message *prepare;
  prepare_message *prepare_specific;

  /* Construct new message */
  prepare          = UTIL_New_Signed_Message();
  prepare_specific = (prepare_message *)(prepare + 1);

  prepare->machine_id = VAR.My_Server_ID;
  prepare->type       = PREPARE;
  prepare->len        = sizeof(prepare_message);
    
  prepare_specific->seq_num = pp->seq_num;
  prepare_specific->view    = pp->view;
  
  /* Now compute the digest of the content and copy it into the digest field */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), prepare_specific->digest);
  
  return prepare;
}

signed_message *ORDER_Construct_Commit(complete_pre_prepare_message *pp)
{
  signed_message *commit;
  commit_message *commit_specific;
  
  /* Construct new message */
  commit          = UTIL_New_Signed_Message();
  commit_specific = (commit_message*)(commit + 1);

  commit->machine_id = VAR.My_Server_ID;
  commit->type       = COMMIT;
  commit->len        = sizeof(commit_message);

  commit_specific->seq_num = pp->seq_num;
  commit_specific->view    = pp->view;
  
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), commit_specific->digest);

  return commit;
}

signed_message *ORDER_Construct_Client_Response(int32u client_id, 
						int32u seq_num)
{
  signed_message *response;
  client_response_message *response_specific;

  /* Construct new message */
  response = UTIL_New_Signed_Message();

  response_specific = (client_response_message*)(response + 1);

  response->machine_id = VAR.My_Server_ID;
  response->type       = CLIENT_RESPONSE;
  response->len        = sizeof(client_response_message);

  response_specific->machine_id = client_id;
  response_specific->seq_num    = seq_num;

  return response;
}

signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
						      int32u *more_to_encode)
{
  signed_message *mess;
  erasure_part *part;
  erasure_part_obj *ep;
  recon_message *r;
  recon_part_header *rph;
  int32u cutoff, bytes;
  char *p;

  mess = UTIL_New_Signed_Message();

  mess->type       = RECON;
  mess->machine_id = VAR.My_Server_ID;
  mess->len        = 0; /* Set below when we add parts */

  r = (recon_message *)(mess + 1);

  r->num_parts = 0; /* Updated as we add parts */

  /* This message may have local Merkle tree digests, and it needs to 
   * fit into a local PO-Request to be ordered, which might have 
   * digests of its own, along with a signed message and a po_request. */
  cutoff = (PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS));
  
  bytes = sizeof(signed_message) + sizeof(recon_message);

  /* Start writing parts right after the recon_message */
  p = (char *)(r+1);

  assert(!UTIL_DLL_Is_Empty(list));

  /* Go through as many message on the list as we can.  Encode each one,
   * then write the part you're supposed to send into the packet. */
  while(bytes < cutoff) {
    UTIL_DLL_Set_Begin(list);

    /* If there are no more messages to encode, stop.  Otherwise, grab one, 
     * see if the part will fit in the message, and encode it. */
    if((ep = (erasure_part_obj *)UTIL_DLL_Front_Message(list)) == NULL) {
      *more_to_encode = 0;
      break;
    }    

    if((bytes + sizeof(recon_part_header) + ep->part_len) < cutoff) {

      /* Write the preorder id of the part being encoded */
      rph = (recon_part_header *)p;
      rph->originator = ep->originator;
      rph->seq_num    = ep->seq_num;

      /* Write the length of the part being encoded, including the erasure
       * part, which contains the message length. This is how many bytes
       * follows the rph. */
      rph->part_len = ep->part_len;

      /* Write the part itself right after the header, and write the 
       * length of the message being encoded. */
      part = (erasure_part *)(rph + 1);
      part->mess_len = ep->part.mess_len;
      
      /* Skip past the erasure_part */
      p = (char *)(part+1);
      
      /* Now write the part itself */
      memcpy(p, ep->buf, ep->part_len - sizeof(erasure_part));
      p += (ep->part_len - sizeof(erasure_part));
      
      /* We wrote this many bytes to the packet */
      bytes += sizeof(recon_part_header) + ep->part_len;

      r->num_parts++;
      UTIL_DLL_Pop_Front(list);
    }
    else {
      *more_to_encode = 1;
      break;
    }
  }
  
  assert(bytes <= cutoff);
  assert(r->num_parts > 0);
  mess->len = bytes - sizeof(signed_message);

  return mess;
}
