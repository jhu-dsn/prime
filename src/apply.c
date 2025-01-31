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

/* Apply messages to the data structures. These functions take a message that
 * has been validated and applies it to the data structures. */
#include <assert.h>
#include <string.h>
#include "data_structs.h"
#include "apply.h"
#include "util/memory.h"
#include "util/alarm.h"
#include "error_wrapper.h"
#include "utility.h"
#include "order.h"
#include "recon.h"
#include "pre_order.h"

/* Gobally Accessible Variables */
extern server_variables   VAR;
extern server_data_struct DATA;

void APPLY_Update      (signed_message *update); 
void APPLY_PO_Request  (signed_message *mess);
void APPLY_PO_Ack      (signed_message *mess);
void APPLY_PO_ARU      (signed_message *mess);
void APPLY_Proof_Matrix(signed_message *mess);
void APPLY_Pre_Prepare (signed_message *mess);
void APPLY_Prepare     (signed_message *mess);
void APPLY_Commit      (signed_message *mess);
void APPLY_Recon       (signed_message *mess);

int32u APPLY_Prepare_Certificate_Ready(ord_slot *slot);
void   APPLY_Move_Prepare_Certificate (ord_slot *slot);
int32u APPLY_Prepare_Matches_Pre_Prepare(signed_message *prepare,
					 complete_pre_prepare_message *pp);

int32u APPLY_Commit_Certificate_Ready  (ord_slot *slot);
void   APPLY_Move_Commit_Certificate   (ord_slot *slot);
int32u APPLY_Commit_Matches_Pre_Prepare(signed_message *commit,
					complete_pre_prepare_message *pp);

/* Apply a signed message to the data structures. */
void APPLY_Message_To_Data_Structs(signed_message *mess) 
{

  switch (mess->type) {   

  case UPDATE:
    APPLY_Update(mess);
    break;

  case PO_REQUEST:
    APPLY_PO_Request(mess);
    break;
    
  case PO_ACK:
    APPLY_PO_Ack(mess);
    break;

  case PO_ARU:
    
    /* If the delay attack is used, the leader ignores PO-ARU messages 
     * and only handles proof matrix messages when it needs to. */
#if DELAY_ATTACK
    if(!UTIL_I_Am_Leader())
      APPLY_PO_ARU(mess);
#else
    APPLY_PO_ARU(mess);
#endif
    break;

  case PROOF_MATRIX:

    /* If the delay attack is used, the leader adds the proof matrix
     * message to a queue and only processes it when it needs to, when
     * it comes time to send the Pre-Prepare. */
#if DELAY_ATTACK
    if(!UTIL_I_Am_Leader())
      APPLY_Proof_Matrix(mess);
#else
    APPLY_Proof_Matrix(mess);
#endif
    break;
    
  case PRE_PREPARE:
    APPLY_Pre_Prepare(mess);
    break;

  case PREPARE:
    APPLY_Prepare(mess);
    break;

  case COMMIT:
    APPLY_Commit(mess);
    break;

  case RECON:
    APPLY_Recon(mess);
    break;

  default:
    Alarm(EXIT, "Unexpected message type in APPLY message: %d\n", mess->type);
    return;
  }
}

void APPLY_Update(signed_message *update)
{
  /* Nothing to do */
}

void APPLY_PO_Request(signed_message *po_request)
{
  po_slot *slot;
  po_request_message *po_request_specific;
  int32u id, seq_num;
  stdit it;

  /* Get the po slot for this message and store the po_request in this slot */
  po_request_specific = (po_request_message*)(po_request+1);

  Alarm(DEBUG, "APPLY PO_REQUEST %d %d\n", 
	po_request->machine_id, po_request_specific->seq_num);

  /* If we've already garbage collected this slot, don't do anything */
  if(po_request_specific->seq_num <= 
     DATA.PO.white_line[po_request->machine_id]) {
    Alarm(DEBUG, "Discarding PO-Request %d %d, already gc\n",
	  po_request->machine_id, po_request_specific->seq_num);
    return;
  }    

  assert((po_request->machine_id >= 1) && 
	 (po_request->machine_id <= NUM_SERVERS));

  slot = UTIL_Get_PO_Slot(po_request->machine_id, po_request_specific->seq_num);
  
  /* If we already have this po request, don't do anything */
  if(slot->po_request) {
    Alarm(DEBUG, "Discarding PO-Request %d %d, already have it.\n",
	  po_request->machine_id, po_request_specific->seq_num);
    return;
  }

  /* Store the po_request if we need it. */
  inc_ref_cnt(po_request); 
  slot->po_request  = po_request;

  PRE_ORDER_Update_ARU();

  slot->num_events = po_request_specific->num_events;

  /* See if we were missing this PO-Request when it became eligible for
   * local execution.  If so, mark that we have it.  Then, if this means
   * we can execute the next global sequence number, try. */
  id      = po_request->machine_id;
  seq_num = po_request_specific->seq_num;
  stdhash_find(&DATA.PO.Pending_Execution[id], &it, &seq_num);

  if(!stdhash_is_end(&DATA.PO.Pending_Execution[id], &it)) {
    ord_slot *o_slot;

    o_slot = *((ord_slot **)stdhash_it_val(&it));
    dec_ref_cnt(o_slot);
    stdhash_erase_key(&DATA.PO.Pending_Execution[id], &seq_num);
    o_slot->num_remaining_for_execution--;

    assert(o_slot->num_remaining_for_execution >= 0);

    Alarm(DEBUG, "Received missing po-request %d %d\n", id, seq_num);

    if(o_slot->num_remaining_for_execution == 0) {
      sp_time t;
      t.sec = 0; t.usec = 0;
      E_queue(ORDER_Attempt_To_Execute_Pending_Commits, 0, 0, t);
    }    

    Alarm(DEBUG, "Filled hole\n");
  }
}

void APPLY_PO_Ack(signed_message *po_ack)
{
  po_slot *slot;
  po_ack_message *po_ack_specific;
  po_ack_part *part;
  int32u p;

  /* Iterate over each ack in the aggregate PO-Ack, and apply it to
   * the correct po slot */
  Alarm(DEBUG, "PO_Ack from %d\n", po_ack->machine_id);

  po_ack_specific = (po_ack_message *)(po_ack+1);
  part            = (po_ack_part *)(po_ack_specific+1);

  for (p = 0; p < po_ack_specific->num_ack_parts; p++) {

    /* Mark if I can use this to increase my knowledge of which PO-Requests
     * from originator it has contiguously received and acknowledged. */
    if(part[p].seq_num > 
       DATA.PO.cum_max_acked[po_ack->machine_id][part[p].originator]) {
      DATA.PO.cum_max_acked[po_ack->machine_id][part[p].originator] = 
	part[p].seq_num;
    }

    /* If we've already garbage collected this slot, don't do anything */
    if(part[p].seq_num <= DATA.PO.white_line[part[p].originator])
      continue;
    
    slot = UTIL_Get_PO_Slot(part[p].originator, part[p].seq_num);
    
    /* TODO --- check to see if digests match -- this should be done
     * in conflict */

    if(!slot->ack_received[po_ack->machine_id]) {
      slot->ack_received[po_ack->machine_id] = TRUE;
      slot->ack_count++;
    }
  }
}

void APPLY_PO_ARU(signed_message *po_aru)
{
  int32u prev_num;
  int32u num;
  po_aru_signed_message *prev, *cur;
  int32u i, val;

  /* If the PO_ARU is contained in a Proof matrix, then it may be a null
   * vector.  Don't apply it in this case. */
  if(po_aru->type != PO_ARU)
    return;

  /* We will store the latest PO-ARU received from each server -- this
   * constitutes the proof */
  Alarm(DEBUG, "PO_ARU from %d\n", po_aru->machine_id);

  prev = &(DATA.PO.cum_acks[po_aru->machine_id]);

  num      = ((po_aru_message*)(po_aru+1))->num;
  prev_num = prev->cum_ack.num;

  /* TODO: We should really check to make sure they are consistent here,
   * rather than just blindly adopting the one with the highest number. */
  if(num >= prev_num) {
    memcpy( (void*)( &DATA.PO.cum_acks[po_aru->machine_id]), 
	    (void*)po_aru, sizeof(po_aru_signed_message));
  }

  /* See if I can use this to increase my knowledge of what the acker
   * has contiguously received with respect to po-requests */
  cur = (po_aru_signed_message *)po_aru;
  for(i = 1; i <= NUM_SERVERS; i++) {
    val = cur->cum_ack.ack_for_server[i-1];

    if(DATA.PO.cum_max_acked[po_aru->machine_id][i] < val)
      DATA.PO.cum_max_acked[po_aru->machine_id][i] = val;
  }
}

void APPLY_Proof_Matrix(signed_message *pm)
{
  int32u s;
  po_aru_signed_message *cum_ack;
  proof_matrix_message *pm_specific;

  /* No need to apply my own Local Proof Matrix */
  if(VAR.My_Server_ID == pm->machine_id)
    return;

  Alarm(DEBUG, "Received a proof matrix from server %d\n", pm->machine_id);

  /* The proof is a collection of po_arus -- apply each one */
  pm_specific = (proof_matrix_message *)(pm + 1);
  
  cum_ack = (po_aru_signed_message *)(pm_specific + 1);

  for(s = 0; s < pm_specific->num_acks_in_this_message; s++)
    APPLY_PO_ARU((signed_message *)&cum_ack[s]);
}

void APPLY_Pre_Prepare (signed_message *mess)
{
  pre_prepare_message *pre_prepare_specific;
  ord_slot *slot;
  int32u index, part_num;

  pre_prepare_specific = (pre_prepare_message *)(mess + 1);

  Alarm(DEBUG, "APPLY Pre_Prepare\n");
  
  /* If we're done forwarding for this slot, and we've already reconciled
   * on this slot and the next, and we've already executed this slot and
   * the next one, then there's no reason to do anything else with this
   * sequence number. */
  if(pre_prepare_specific->seq_num <= DATA.ORD.forwarding_white_line &&
     (pre_prepare_specific->seq_num+1) <= DATA.ORD.recon_white_line &&
     (pre_prepare_specific->seq_num+1) <= DATA.ORD.ARU)
    return;
  
  /* Something to do: Get the slot */
  slot = UTIL_Get_ORD_Slot(pre_prepare_specific->seq_num);

  /* If we've already collected all of the parts, ignore */
  if(slot->collected_all_parts)
    return;

  slot->seq_num     = pre_prepare_specific->seq_num;
  slot->view        = pre_prepare_specific->view;
  slot->total_parts = pre_prepare_specific->total_parts;
  part_num          = pre_prepare_specific->part_num;

  slot->complete_pre_prepare.seq_num = slot->seq_num;
  slot->complete_pre_prepare.view    = slot->view;

  /* If we need this part, store it.  Then see if we've now collected
   * all of the parts. */
  if(slot->pre_prepare_parts[part_num] == 0) {

    slot->pre_prepare_parts[part_num] = 1;
    Alarm(DEBUG, "Storing Pre-Prepare part %d for seq %d\n",
          part_num, slot->seq_num);

    if(part_num == 1)
      index = 0;
    else
      index = (3*NUM_FAULTS+1) / 2;

    /* Copy the bytes of this Pre-Prepare into the complete PP */
    Alarm(DEBUG, "Copying part %d to starting index %d\n", part_num, index);
    memcpy((byte *)(slot->complete_pre_prepare.cum_acks + index),
           (byte *)(pre_prepare_specific + 1),
           sizeof(po_aru_signed_message) *
           pre_prepare_specific->num_acks_in_this_message);
    
    slot->num_parts_collected++;
    
    if(slot->num_parts_collected == slot->total_parts) {
      slot->collected_all_parts = 1;
      slot->should_handle_complete_pre_prepare = 1;

      /* If I'm the leader, mark that I've forwarded all parts because
       * I never go and forward them. */
      if(UTIL_I_Am_Leader()) {
	slot->num_forwarded_parts = slot->total_parts;
	ORDER_Update_Forwarding_White_Line();
      }

      /* A Prepare certificate could be ready if we get some Prepares
       * before we get the Pre-Prepare. */
      if(APPLY_Prepare_Certificate_Ready(slot))
        APPLY_Move_Prepare_Certificate(slot);
    }
  }
}

void APPLY_Prepare(signed_message *prepare)
{
  prepare_message *prepare_specific;
  ord_slot  *slot;

  Alarm(DEBUG, "%d APPLY_Prepare\n",VAR.My_Server_ID);

  prepare_specific = (prepare_message *)(prepare+1);

  /* If we've already executed this seq, discard */
  if(prepare_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(prepare_specific->seq_num);
  assert(slot->seq_num == prepare_specific->seq_num);

  if (slot->ordered || slot->bound) 
    return;

  /* If I don't already have a Prepare from this server, store it */
  if(slot->prepare[prepare->machine_id] == NULL) {
    inc_ref_cnt(prepare);
    slot->prepare[prepare->machine_id] = prepare;

    Alarm(DEBUG,"PREPARE %d %d \n", prepare, get_ref_cnt(prepare) );

    if(APPLY_Prepare_Certificate_Ready(slot))
      APPLY_Move_Prepare_Certificate(slot);
  }
}

int32u APPLY_Prepare_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **prepare;
  int32u pcount, sn;

  /* Need a Pre_Prepare for a Prepare Certificate to be ready */
  if(slot->collected_all_parts == 0)
    return 0;

  pp   = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  prepare = (signed_message **)slot->prepare;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(prepare[sn] != NULL) {
      if(APPLY_Prepare_Matches_Pre_Prepare(prepare[sn], pp))
        pcount++;
      else
        Alarm(EXIT,"PREPARE didn't match pre-prepare while "
              "checking for prepare certificate.\n");
    }
  }

  /* If we have the Pre-Prepare and 2f Prepares, we're good to go */
  if (pcount >= VAR.Faults * 2) {
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u APPLY_Prepare_Matches_Pre_Prepare(signed_message *prepare,
					 complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  prepare_message *prepare_specific;
  byte digest[DIGEST_SIZE+1];

  seq_num = pp->seq_num;
  view    = pp->view;

  prepare_specific = (prepare_message*)(prepare+1);

  if(view != prepare_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, prepare_specific->view,
          prepare_specific->seq_num);
    return 0;
  }

  if(seq_num != prepare_specific->seq_num)
    return 0;

  /* Make a digest of the content of the pre_prepare, then compare it
   * to the digest in the Prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  /* This compare was commented out */
  if(!OPENSSL_RSA_Digests_Equal(digest, prepare_specific->digest)) {
    Alarm(PRINT, "Digests don't match.\n");
    return 0;
  }

  return 1;
}

void APPLY_Move_Prepare_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **prepare_src;

  Alarm(DEBUG, "Made Prepare Certificate\n");
  
  pcount      = 0;
  prepare_src = (signed_message **)slot->prepare;

  /*Copy the completed Pre-Prepare into the Prepare Certificate */
  memcpy(&slot->prepare_certificate.pre_prepare, &slot->complete_pre_prepare,
         sizeof(complete_pre_prepare_message));

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if (prepare_src[sn] != NULL) {
      
      if(APPLY_Prepare_Matches_Pre_Prepare(prepare_src[sn],
                                     &slot->prepare_certificate.pre_prepare)) {
        slot->prepare_certificate.prepare[sn] = prepare_src[sn];
        prepare_src[sn] = NULL;
      } else {
        Alarm(EXIT,"PREPARE didn't match pre-prepare while "
              "moving prepare certificate.\n");
      }
    }
  }

  /* Mark that we have a Prepare Certificate.*/
  slot->prepare_certificate_ready = 1;
  slot->bound = 1;
}

void APPLY_Commit(signed_message *commit)
{
  commit_message *commit_specific;
  ord_slot *slot;

  Alarm(DEBUG, "%d APPLY_COMMIT\n",VAR.My_Server_ID);

  commit_specific = (commit_message*)(commit+1);

  /* If we've already globally executed this seq, discard */
  if(commit_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(commit_specific->seq_num);
  
  if(slot->ordered)
    return;

  /* If I have not yet received a commit from this server, store it and
   * see if a commit certificate is ready. */
  if(slot->commit[commit->machine_id] == NULL) {
    inc_ref_cnt(commit);
    slot->commit[commit->machine_id] = commit;
    
    if(APPLY_Commit_Certificate_Ready(slot))
      APPLY_Move_Commit_Certificate(slot);
  }
}

int32u APPLY_Commit_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **commit;
  int32u pcount;
  int32u sn;

  if(slot->collected_all_parts == 0)
    return 0;

  pp = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  commit = (signed_message **)slot->commit;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(commit[sn] != NULL) {
      if(APPLY_Commit_Matches_Pre_Prepare(commit[sn], pp))
	pcount++;
      else
	Alarm(EXIT, "COMMIT didn't match Pre-Prepare\n");
    }
  }

  if(pcount >= (VAR.Faults * 2 + 1)) {
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u APPLY_Commit_Matches_Pre_Prepare(signed_message *commit,
					complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  commit_message *commit_specific;
  byte digest[DIGEST_SIZE+1]; 

  seq_num = pp->seq_num;
  view    = pp->view;
  
  commit_specific = (commit_message*)(commit+1);

  if(view != commit_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, commit_specific->view,
          commit_specific->seq_num);
    return 0;
  }

  if(seq_num != commit_specific->seq_num)
    return 0;
  
  /* Make a digest of the content of the pre_prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  if(!OPENSSL_RSA_Digests_Equal(digest, commit_specific->digest))
    return 0;
  
  return 1;
}

void APPLY_Move_Commit_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **commit_src;
  complete_pre_prepare_message *pp;

  Alarm(DEBUG, "Made commit certificate.\n");

  pcount     = 0;
  commit_src = (signed_message **)slot->commit;
  
  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if((commit_src)[sn] != NULL) {
      Alarm(DEBUG,"APPLY_Move_Commit_Certificate %d\n", commit_src[sn]);

      if(slot->prepare_certificate_ready)
	pp = &slot->prepare_certificate.pre_prepare;
      else
	pp = &slot->complete_pre_prepare;

      if(APPLY_Commit_Matches_Pre_Prepare(commit_src[sn], pp)) {
	slot->commit_certificate.commit[sn] = commit_src[sn];
	commit_src[sn] = NULL;
      } else {
	Alarm(EXIT, "Commit didn't match pre-prepare while "
	      "moving commit certificate.\n");
	return;
      }
    }
  }

  /* The next time that we process a commit, we should execute. */
  slot->execute_commit = 1;
  slot->ordered = 1;
}

void APPLY_Recon(signed_message *recon)
{
  int32u i;
  recon_message *r;
  recon_part_header *rph;
  erasure_part *part;
  recon_slot *slot;
  po_slot *po_slot;
  char *p;
  int32u *ip;
  int32u index;

  r = (recon_message *)(recon + 1);
  p = (char *)(r + 1);

  for(i = 0; i < r->num_parts; i++) {

    rph  = (recon_part_header *)p;
    part = (erasure_part *)(rph + 1);

    /* If we've already contiguously collected PO-Requests for this or higher,
     * then we must already have it. Or if I've already garbage collected
     * this one, I must have it already*/
    if(rph->seq_num <= DATA.PO.aru[rph->originator] ||
       rph->seq_num <= DATA.PO.white_line[rph->originator]) {

      Alarm(DEBUG, "Discarding Recon for %d %d from %d\n",
	    rph->originator, rph->seq_num, recon->machine_id);

      /* Move to the next part and continue */
      p = (char *)part;
      p += rph->part_len;
      continue;
    }

    /* Even though I haven't collected contiguously, I may have the PO
     * request being reconciled.  Skip it in this case. */
    po_slot = UTIL_Get_PO_Slot_If_Exists(rph->originator, rph->seq_num);
    if(po_slot && po_slot->po_request) {
      /* Move to the next part and continue */
      p = (char *)part;
      p += rph->part_len;
      continue;
    }
    
    /* We want to process this part.  Store a copy of it in the slot if
     * we need it. */
    slot = UTIL_Get_Recon_Slot(rph->originator, rph->seq_num);

    /* If we've already decoded this one, continue */
    if(slot->decoded) {
      p = (char *)part;
      p += rph->part_len;
      Alarm(DEBUG, "Ignoring part for %d %d, already decoded\n",
	    rph->originator, rph->seq_num);
      continue;
    }

    if(slot->part_collected[recon->machine_id] == 0) {

      /* Mark that we have the part from this server */
      slot->part_collected[recon->machine_id] = 1;
      slot->num_parts_collected++;
      
      Alarm(DEBUG, "Stored Local Recon for (%d, %d) from %d\n", 
	    rph->originator, rph->seq_num, recon->machine_id);

      /* Copy the part into the buffer */
      memcpy(slot->parts[recon->machine_id], part, rph->part_len);
      
      ip = (int32u *)(part + 1);
      index = ip[0];
      Alarm(DEBUG, "Part had index %d\n", index);

      /* If we have enough parts, we should decode */
      if(slot->num_parts_collected == (VAR.Faults + 1))
	slot->should_decode = 1;

      /* Move on to the next one */
      p = (char *)part;
      p += rph->part_len;
    }
  }
}
