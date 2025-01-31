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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/alarm.h"
#include "util/memory.h"
#include "order.h"
#include "data_structs.h"
#include "utility.h"
#include "util_dll.h"
#include "def.h"
#include "apply.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "dispatcher.h"
#include "signature.h"
#include "erasure.h"
#include "recon.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void   ORDER_Upon_Receiving_Pre_Prepare  (signed_message *mess);
void   ORDER_Upon_Receiving_Prepare      (signed_message *mess);
void   ORDER_Upon_Receiving_Commit       (signed_message *mess);
void   ORDER_Periodically                (int dummy, void *dummyp);
void   ORDER_Execute_Update              (signed_message *mess);
void   ORDER_Flood_Pre_Prepare           (signed_message *mess);
void   ORDER_Update_Forwarding_White_Line(void);
void   ORDER_Send_Commit                 (complete_pre_prepare_message *pp);
int32u ORDER_Ready_To_Execute            (ord_slot *o_slot);

void ORDER_Dispatcher(signed_message *mess)
{
  /* All messages are of type signed_message. We assume that:
   *
   * THERE ARE NO CONFLICTS
   *
   * THE MESSAGE HAS BEEN APPLIED TO THE DATA STRUCTURE
   *
   * THE MESSAGE HAS PASSED VALIDATION
     */
  switch (mess->type) {
    
  case PRE_PREPARE:
    ORDER_Upon_Receiving_Pre_Prepare(mess);
    break;
    
  case PREPARE:
    ORDER_Upon_Receiving_Prepare(mess);
    break;

  case COMMIT:
    ORDER_Upon_Receiving_Commit(mess);
    break;
    
  default:
    INVALID_MESSAGE("ORDER Dispatcher");
  }
}

void ORDER_Initialize_Data_Structure()
{
  DATA.ORD.ARU                    = 0;
  DATA.ORD.events_ordered         = 0;
  DATA.ORD.seq                    = 1;

  stdhash_construct(&DATA.ORD.History, sizeof(int32u), 
		    sizeof(ord_slot *), NULL, NULL, 0);
  
  stdhash_construct(&DATA.ORD.Pending_Execution, sizeof(int32u),
		    sizeof(ord_slot *), NULL, NULL, 0);

  UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);

  Alarm(PRINT_LOCAL, "Initialized Ordering data structure.\n");

  /* If I'm the leader, try to start sending Pre-Prepares */
  if (UTIL_I_Am_Leader())
    ORDER_Periodically(0, NULL);
}

void ORDER_Periodically(int dummy, void *dummyp)
{
  sp_time t;

  ORDER_Send_One_Pre_Prepare(TIMEOUT_CALLER);
  t.sec  = PRE_PREPARE_SEC; 
  t.usec = PRE_PREPARE_USEC;
  E_queue(ORDER_Periodically, 0, NULL, t);
}

int32u ORDER_Send_One_Pre_Prepare(int32u caller)
{
  signed_message *mset[NUM_SERVERS];
  int32u num_parts, i;
  double time;

  /* Make sure enough time has elapsed since we've sent a Pre-Prepare */
  UTIL_Stopwatch_Stop(&DATA.ORD.pre_prepare_sw);
  time = UTIL_Stopwatch_Elapsed(&DATA.ORD.pre_prepare_sw);
  if(time < (PRE_PREPARE_USEC / 1000000.0))
    return 0;

#if DELAY_ATTACK
  while(!UTIL_DLL_Is_Empty(&DATA.PO.proof_matrix_dll) &&
	UTIL_DLL_Elapsed_Front(&DATA.PO.proof_matrix_dll) > DELAY_TARGET) {
    APPLY_Proof_Matrix(UTIL_DLL_Front_Message(&DATA.PO.proof_matrix_dll));
    UTIL_DLL_Pop_Front(&DATA.PO.proof_matrix_dll);
  }
#endif

  if(PRE_ORDER_Latest_Proof_Sent())
    return 0;
  
  /* Construct the Pre-Prepare */
  ORDER_Construct_Pre_Prepare(mset, &num_parts);
    
  PRE_ORDER_Update_Latest_Proof_Sent();

  for(i = 1; i <= num_parts; i++) {
    Alarm(DEBUG, "Add: Pre-Prepare part %d \n", i);
    SIG_Add_To_Pending_Messages(mset[i], BROADCAST, 
				UTIL_Get_Timeliness(PRE_PREPARE));
    dec_ref_cnt(mset[i]);
  }

  UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);

  return 1;
}

void ORDER_Upon_Receiving_Pre_Prepare(signed_message *mess)
{
  signed_message *prepare;
  ord_slot *slot;
  pre_prepare_message *pp_specific;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  int32u part_num;
  int32u i;

  Alarm(DEBUG,"%d Received Pre-Prepare\n", VAR.My_Server_ID);

  pp_specific = (pre_prepare_message *)(mess+1);
  part_num    = pp_specific->part_num;
  
  /* If we're done forwarding for this slot, and we've already reconciled
   * on this slot and the next, and we've already executed this slot and
   * the next one, then there's no reason to do anything else with this
   * sequence number. */
  if(pp_specific->seq_num <= DATA.ORD.forwarding_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.recon_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.ARU)
    return;

  slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);
  
  /* If we already flooded this part of the PP, don't do it
   * again. Otherwise, flood it if I'm not the leader. */
  if (slot->forwarded_pre_prepare_parts[part_num])
    Alarm(DEBUG, "Not re-forwarding PP part %d\n", part_num);
  else if(!UTIL_I_Am_Leader())
    ORDER_Flood_Pre_Prepare(mess);

  /* If we now have the complete Pre-Prepare for the first time, do the 
   * following:
   * 
   *  1. If I'm a non-leader, send a Prepare.
   *
   *  2. Apply the PO-ARUs in the Proof Matrix.
   *
   *  3. Perform reconciliation on this slot.  Also try to perform it on
   *     the next slot, because that slot might not have been able to 
   *     reconcile if we received PP i+1 before PP i. */
  if(slot->should_handle_complete_pre_prepare) {

    slot->should_handle_complete_pre_prepare = 0;

    /* Non-leaders should send a Prepare */
    if(!UTIL_I_Am_Leader()) {

      /* Construct a Prepare Message based on the Pre-Prepare */
      prepare = ORDER_Construct_Prepare(&slot->complete_pre_prepare);

      Alarm(DEBUG, "Add: Prepare\n");
      SIG_Add_To_Pending_Messages(prepare, BROADCAST, 
				  UTIL_Get_Timeliness(PREPARE));
      dec_ref_cnt(prepare);
    }

    /* Apply the PO-ARUs contained in the proof matrix */
    complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
    cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;

    for(i = 0; i < NUM_SERVERS; i++) {
      signed_message *m = (signed_message *)&cum_acks[i];

      /* Some of the rows in the proof matrix might be null vectors, so 
       * only apply if it is really a PO_ARU message. */
      if(m->type == PO_ARU)
	APPLY_Message_To_Data_Structs(m);
    }

    /* Try to reconcile on the current slot, then try to reconcile on the
     * next one in case it was waiting for a Pre-Prepare to fill the hole. */
    RECON_Do_Recon(slot);
      
    slot = UTIL_Get_ORD_Slot_If_Exists(pp_specific->seq_num + 1);
    if(slot != NULL)
      RECON_Do_Recon(slot);
  }
}

void ORDER_Upon_Receiving_Prepare(signed_message *mess) 
{
  ord_slot *slot;
  prepare_message *prepare_specific;

  prepare_specific = (prepare_message*)(mess+1);

  if(prepare_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* When the Prepare is applied, we call a function to see if a Prepare
   * certificate is ready.  If so, we set the send_commit_on_prepare 
   * bit in the slot. */
  
  slot = UTIL_Get_ORD_Slot_If_Exists(prepare_specific->seq_num);

  if(slot == NULL) 
    return;
  
  Alarm(DEBUG,"%d slot->bound %d\n",   VAR.My_Server_ID, slot->bound);
  Alarm(DEBUG,"%d Received Prepare\n", VAR.My_Server_ID);

  if(slot->prepare_certificate_ready) {
    assert(slot->collected_all_parts);

    if(slot->sent_commit == 0) {
      slot->sent_commit = 1;
      ORDER_Send_Commit(&slot->prepare_certificate.pre_prepare);
    }
  }
}

void ORDER_Send_Commit(complete_pre_prepare_message *pp)
{
  signed_message *commit;

  /* Construct a Prepare Message based on the Pre-Prepare */
  commit = ORDER_Construct_Commit(pp);
  
  Alarm(DEBUG, "Add: Commit\n");
  SIG_Add_To_Pending_Messages(commit, BROADCAST, UTIL_Get_Timeliness(COMMIT));
  dec_ref_cnt(commit);
}

void ORDER_Upon_Receiving_Commit(signed_message *mess)
{
  ord_slot *slot;
  commit_message *commit_specific;

  commit_specific = (commit_message*)(mess+1);

  slot = UTIL_Get_ORD_Slot_If_Exists(commit_specific->seq_num);

  if(slot == NULL)
    return;
  
  /* Execute the commit certificate  only the first time that we get it */
  if(slot->execute_commit) {
    slot->execute_commit = 0;
    ORDER_Execute_Commit(slot);
  }
}

int32u ORDER_Ready_To_Execute(ord_slot *o_slot)
{
  complete_pre_prepare_message *pp;
  complete_pre_prepare_message *prev_pp;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  int32u gseq, i, j;
  int32u prev_pop[NUM_SERVER_SLOTS];
  int32u cur_pop[NUM_SERVER_SLOTS];
  stdit it;

  if(o_slot->prepare_certificate_ready)
    pp = &o_slot->prepare_certificate.pre_prepare;
  else
    pp = &o_slot->complete_pre_prepare;
  
  gseq = pp->seq_num;

  /* First check to see if we've globally executed the previous
   * sequence number. */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  /* The previous slot is allowed to be NULL only if this is the first seq */
  if( (prev_ord_slot == NULL && gseq != 1) ||
      (prev_ord_slot != NULL && prev_ord_slot->executed == 0) ) {

    /* We can't execute this global slot yet because we have not yet
     * executed the previous global slot.  Put it on hold. */
    Alarm(DEBUG, "Ordered slot %d but my aru is %d!\n", gseq, DATA.ORD.ARU);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }

  /* If we already know there are po-requests missing, we can't execute */
  if(o_slot->num_remaining_for_execution > 0) {
    Alarm(DEBUG, "%d requests missing for gseq %d\n", 
	  o_slot->num_remaining_for_execution, gseq);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }

  /* See which PO-Requests are now eligible for execution. */
  if(prev_ord_slot == NULL) {
    assert(gseq == 1);

    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = 0;
  }
  else {
    if(prev_ord_slot->prepare_certificate_ready)
      prev_pp = &prev_ord_slot->prepare_certificate.pre_prepare;
    else {
      prev_pp = &prev_ord_slot->complete_pre_prepare;
      assert(prev_ord_slot->collected_all_parts);
    }

    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }

  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);

  for(i = 1; i <= NUM_SERVERS; i++) {
    for(j = prev_pop[i] + 1; j <= cur_pop[i]; j++) {

      p_slot = UTIL_Get_PO_Slot_If_Exists(i, j);

      if(p_slot == NULL || p_slot->po_request == NULL) {
        Alarm(DEBUG, "Seq %d not ready, missing: %d %d\n", gseq, i, j);

        o_slot->num_remaining_for_execution++;
        Alarm(DEBUG, "Setting ord_slots num_remaining to %d\n",
              o_slot->num_remaining_for_execution);

        /* Insert a pointer to (i, j) into the map */
        inc_ref_cnt(o_slot);
        stdhash_insert(&DATA.PO.Pending_Execution[i], &it, &j, &o_slot);
      }
    }
  }

  /* If any PO-Request was missing, the slot is not ready to be executed. */
  if(o_slot->num_remaining_for_execution > 0) {
    Alarm(DEBUG, "Not executing global seq %d, waiting for %d requests\n",
          gseq, o_slot->num_remaining_for_execution);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }
  
  return 1;
}

void ORDER_Execute_Commit(ord_slot *o_slot)
{
  complete_pre_prepare_message *prev_pp;
  signed_message *po_request;
  po_request_message *po_request_specific;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  int32u prev_pop[NUM_SERVER_SLOTS];
  int32u cur_pop[NUM_SERVER_SLOTS];
  int32u gseq, i, j, k, num_events;
  signed_message *event;
  char *p;
  int32u wa_bytes;
  complete_pre_prepare_message *pp;
  //sp_time t;

  assert(o_slot);

  if(o_slot->prepare_certificate_ready)
    pp = &o_slot->prepare_certificate.pre_prepare;
  else
    pp = &o_slot->complete_pre_prepare;

  gseq = pp->seq_num;

  if(!ORDER_Ready_To_Execute(o_slot)) {
    Alarm(DEBUG, "Not yet ready to execute seq %d\n", gseq);
    return;
  }

  Alarm(DEBUG, "Executing Commit for Ord seq %d!\n", gseq);

  /* Get the previous ord_slot if it exists. If it doesn't exist,
   * then this better be the first sequence number! */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  if(prev_ord_slot == NULL) {
    assert(gseq == 1);
    
    Alarm(DEBUG, "Gseq was 1, setting all in prev_pop to 0\n");
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = 0;
  }
  else {
    assert(prev_ord_slot->executed);

    if(prev_ord_slot->prepare_certificate_ready)
      prev_pp = &(prev_ord_slot->prepare_certificate.pre_prepare);
    else
      prev_pp = &prev_ord_slot->complete_pre_prepare;
    
    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }
  
  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);

#if 0
#if 0
 Alarm(PRINT, "Prevpop = [ ");
  for(i = 1; i <= NUM_SERVERS; i++)
    Alarm(PRINT, "%d ", prev_pop[i]);
  Alarm(PRINT, "]\n");
#endif


  Alarm(PRINT, "Cur_pop = [ ");
  for(i = 1; i <= NUM_SERVERS; i++) {
    Alarm(PRINT, "%d ", cur_pop[i]);
  }  
  Alarm(PRINT, "]\n");

  UTIL_Print_Time();
#endif
  
  /* Mark this slot as executed */
  o_slot->executed = 1;
  assert(gseq == (DATA.ORD.ARU + 1));
  DATA.ORD.ARU++;

  for(i = 1; i <= NUM_SERVERS; i++) {
    for(j = prev_pop[i] + 1; j <= cur_pop[i]; j++) {
      
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, j);
      assert(p_slot);

      po_request_specific = NULL;
      po_request          = p_slot->po_request;
      assert(po_request);

      po_request_specific = (po_request_message *)(po_request + 1);
      num_events          = po_request_specific->num_events;
      
      DATA.ORD.events_ordered += num_events;
      Alarm(PRINT_LOCAL, "Set events_ordered to %d\n", 
	    DATA.ORD.events_ordered);

      /* We now need to execute these events we just ordered. Go through
       * all of the events in the PO-Request and execute each one. */
      
      p = (char *)(po_request_specific + 1);
      for(k = 0; k < num_events; k++) {
	event = (signed_message *)p;
	ORDER_Execute_Event(event);

	/* If this is a wide-area message, then some digest bytes may 
	 * have been appended.  Take these into consideration. */
	wa_bytes = 0;
	p += event->len + sizeof(signed_message) + wa_bytes;
      }

      /* We've executed all of the events in pre-order slot, so clean
       * it up. */
      PRE_ORDER_Garbage_Collect_PO_Slot(i, j);
    }
  }

  /* Garbage collect seq-1 when I commit seq */
  ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq-1);
  
  //t.sec = 0;
  //t.usec = 1000;
  //E_queue(ORDER_Attempt_To_Execute_Pending_Local_Commits, 0, 0, t);
  ORDER_Attempt_To_Execute_Pending_Commits(0, 0);
}

void ORDER_Attempt_To_Execute_Pending_Commits(int dummy, void *dummyp)
{
  ord_slot *slot;
  int32u i;
  stdit it;

  i = DATA.ORD.ARU+1;

  stdhash_find(&DATA.ORD.Pending_Execution, &it, &i);

  if(!stdhash_is_end(&DATA.ORD.Pending_Execution, &it)) {
    slot = *((ord_slot **)stdhash_it_val(&it));

    Alarm(DEBUG, "Went back and tried to execute %d\n", i);

    /* If it's not ready, it will be re-added to the hash */
    ORDER_Execute_Commit(slot);
  }
}

void ORDER_Execute_Event(signed_message *event)
{
  /* There should be one case: we execute an update */
  assert(event->type == UPDATE);

  Alarm(DEBUG, "Executing an update with timestamp %d\n",
	((signed_update_message *)event)->update.time_stamp);
  ORDER_Execute_Update(event);
}

void ORDER_Execute_Update(signed_message *mess)
{
  signed_update_message *u;

  assert(mess->type == UPDATE);

  BENCH.updates_executed++;
  if(BENCH.updates_executed == 1)
    UTIL_Stopwatch_Start(&BENCH.test_stopwatch);

  if(BENCH.updates_executed % 50 == 0)
    Alarm(PRINT, "Executed %d updates\n", BENCH.updates_executed);

  u = (signed_update_message *)mess;
  Alarm(DEBUG, "Ordered update with timestamp %d\n", u->update.time_stamp);

  if(u->update.server_id == VAR.My_Server_ID)
    UTIL_Respond_To_Client(mess->machine_id, u->update.time_stamp);

  UTIL_State_Machine_Output(u);

  if(BENCH.updates_executed == BENCHMARK_END_RUN) {
    ORDER_Cleanup();
    exit(0);
  }
}

void ORDER_Flood_Pre_Prepare(signed_message *mess)
{
  int32u part_num;
  pre_prepare_message *pp_specific;
  ord_slot *slot;

  pp_specific = (pre_prepare_message *)(mess+1);
  part_num    = pp_specific->part_num;
  
  slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);

  if(!UTIL_I_Am_Leader()) {
#if THROTTLE_OUTGOING_MESSAGES
    int32u dest_bits, i;
    /* Send it to all but the leader and myself */
    dest_bits = 0;
    for(i = 1; i <= NUM_SERVERS; i++) {
      if(i == UTIL_Leader() || i == VAR.My_Server_ID)
	continue;
      UTIL_Bitmap_Set(&dest_bits, i);
    }
    /* Note: Can't just get the traffic class from UTIL_Get_Timeliness 
     * because we need to distinguish flooded Pre-Prepares from regular
     * Pre-Prepares. */
    NET_Add_To_Pending_Messages(mess, dest_bits, BOUNDED_TRAFFIC_CLASS);
#else
    UTIL_Broadcast(mess);
    BENCH.num_flooded_pre_prepares++;
#endif
    slot->forwarded_pre_prepare_parts[part_num] = TRUE;
    slot->num_forwarded_parts++;
 
    /* If we've forwarded all parts, try to update the white line */
    if(slot->num_forwarded_parts == slot->total_parts)
      ORDER_Update_Forwarding_White_Line();
  }
}

void ORDER_Update_Forwarding_White_Line()
{
  ord_slot *slot;
  int32u seq;

  while(1) {

    seq = DATA.ORD.forwarding_white_line + 1;

    slot = UTIL_Get_ORD_Slot_If_Exists(seq);
    
    if(slot != NULL && 
       slot->collected_all_parts && 
       slot->num_forwarded_parts == slot->total_parts) {
      
      ORDER_Attempt_To_Garbage_Collect_ORD_Slot(seq);
      DATA.ORD.forwarding_white_line++;
    }
    else
      break;
  }
}

void ORDER_Attempt_To_Garbage_Collect_ORD_Slot(int32u seq)
{
  int32u i;
  ord_slot *slot;
  ord_slot *pending_slot;

  slot = UTIL_Get_ORD_Slot_If_Exists(seq);

  if(slot == NULL)
    return;
  
  /* Need to have received and forwarded all parts of the Pre-Prepare */
  if(slot->collected_all_parts == 0 || DATA.ORD.forwarding_white_line < seq)
    return;

  /* Need to have globally ordered this slot and the next one */
  if(DATA.ORD.ARU < (seq+1))
    return;

  /* Need to have reconciled this slot and the next one */
  if(DATA.ORD.recon_white_line < (seq+1))
    return;

  /* We'll never need or allocate this slot again, so clear it out. */
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(slot->prepare[i])
      dec_ref_cnt(slot->prepare[i]);
    
    if(slot->commit[i])
      dec_ref_cnt(slot->commit[i]);
    
    if(slot->prepare_certificate.prepare[i])
      dec_ref_cnt(slot->prepare_certificate.prepare[i]);
    
    if(slot->commit_certificate.commit[i])
      dec_ref_cnt(slot->commit_certificate.commit[i]);
  }

  /* If this slot was pending execution, we can now mark it as not pending */
  pending_slot = UTIL_Get_Pending_ORD_Slot_If_Exists(seq);
  if(pending_slot != NULL) {
    stdhash_erase_key(&DATA.ORD.Pending_Execution, &seq);
    dec_ref_cnt(pending_slot);
  }

  /* Now get rid of the slot itself */
  dec_ref_cnt(slot);
  stdhash_erase_key(&DATA.ORD.History, &seq);

  if(seq % 20 == 0)
    Alarm(DEBUG, "Garbage collected Local ORD slot %d\n", seq);
}

void ORDER_Cleanup()
{
  int32u i;
  
  UTIL_Stopwatch_Stop(&BENCH.test_stopwatch);

  Alarm(PRINT, "----------------Statistics----------------------\n");
  Alarm(PRINT, "Average updates per PO-Request: %f\n", 
	(float) BENCH.total_updates_requested / 
	BENCH.num_po_requests_sent);
  
  Alarm(PRINT, "Average acks per PO-Ack: %f\n",
	(float) BENCH.num_acks / BENCH.num_po_acks_sent);
  
  Alarm(PRINT, "Number of flooded Pre-Prepares: %d\n", 
	BENCH.num_flooded_pre_prepares);

  Alarm(PRINT, "Total number of signatures: %d\n", BENCH.num_signatures);
  Alarm(PRINT, "Average signature batch size: %f\n",
	(double)BENCH.total_signed_messages / BENCH.num_signatures);
  Alarm(PRINT, "Maximum signature batch size: %d\n",
	BENCH.max_signature_batch_size);
  
  Alarm(PRINT, "Number of messages sent of type:\n");
  for(i = 1; i < CLIENT_RESPONSE+1; i++)
    Alarm(PRINT, "  %-15s ---> %d\n", UTIL_Type_To_String(i), 
	  BENCH.signature_types[i]);

  UTIL_DLL_Clear(&DATA.PO.po_request_dll);
  UTIL_DLL_Clear(&DATA.PO.proof_matrix_dll);

  UTIL_DLL_Clear(&DATA.SIG.pending_messages_dll);

  for(i = 1; i <= 300; i++) {
    if(NET.client_sd[i] > 2)
      close(NET.client_sd[i]);
  }
  Alarm(PRINT, "------------------------------------------------\n");
  Alarm(PRINT, "Throughput = %f updates/sec\n",
	(double) DATA.ORD.events_ordered / 
	UTIL_Stopwatch_Elapsed(&BENCH.test_stopwatch));
  
  fclose(BENCH.state_machine_fp);

  sleep(2);
}
