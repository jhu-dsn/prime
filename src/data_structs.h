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

#ifndef PRIME_DATA_STRUCTS_H
#define PRIME_DATA_STRUCTS_H

#include <stdio.h>
#include "def.h"
#include "util/arch.h"
#include "util/sp_events.h"
#include "stdutil/stdhash.h"
#include "openssl_rsa.h"
#include "stopwatch.h"
#include "util_dll.h"
#include "packets.h"

#define MAX_PRE_PREPARE_PARTS 2

/* Public Functions */
void DAT_Initialize(void); 

typedef struct server_variables_dummy {
  int32u My_Server_ID;
  int32u Faults;
} server_variables;

typedef struct network_variables_dummy {
  int32    My_Address;
  int32u   program_type;

  /* Client socket descriptor handling */
  int32    sd;                       /* To respond to clients              */
  int32    listen_sd;                /* To listen for incoming connections */
  int32    client_sd[NUM_CLIENTS+1]; /* Which sd is for which client       */

  /* Stores the IP address of each server, read from configuration file  */
  int32 server_address[NUM_SERVER_SLOTS];

#ifdef SET_USE_SPINES
  channel  Spines_Channel;
  int32 server_address_spines[NUM_SERVER_SLOTS];
#endif

  int16u  Client_Port;

  int16u  Bounded_Port;
  int32   Bounded_Channel;
  int32   Bounded_Mcast_Address;
  int16u  Bounded_Mcast_Port;
  channel Bounded_Mcast_Channel;

  int16u  Timely_Port;
  int32   Timely_Channel;
  int32   Timely_Mcast_Address;
  int16u  Timely_Mcast_Port;
  channel Timely_Mcast_Channel;

  int16u  Recon_Port;
  channel Recon_Channel;

  dll_struct pending_messages_dll[NUM_TRAFFIC_CLASSES];
  double tokens[NUM_TRAFFIC_CLASSES];
  util_stopwatch sw[NUM_TRAFFIC_CLASSES];

} network_variables;

typedef struct dummy_net_struct {
  signed_message *mess;
  int32u server_id;
  int32u site_id;

  int32u dest_bits;
  int32u num_remaining_destinations;
  int32u destinations[NUM_SERVER_SLOTS];

  int32u timeliness;

} net_struct;

typedef struct dummy_benchmark_struct {
  int32u updates_executed;

  int32u num_po_requests_sent;
  int32u total_updates_requested;

  int32u num_flooded_pre_prepares;

  int32u num_po_acks_sent;
  int32u num_acks;
  double total_bits_sent[3];
  int32u clock_started;

  double bits[25];

  int32u num_signatures;
  int32u total_signed_messages;
  int32u max_signature_batch_size;
  int32u signature_types[CLIENT_RESPONSE+1];

  double num_throttle_sends;

  util_stopwatch test_stopwatch;
  util_stopwatch sw;
  util_stopwatch total_test_sw;

  FILE *state_machine_fp;

} benchmark_struct;

/* Pre-Order Data structures*/
typedef struct dummy_po_data_struct {

  /* For each server, what is the last one I've sent a PO-Ack for */
  int32u  max_acked[NUM_SERVER_SLOTS];

  /* For each server, I've collected PO-Requests contiguously up to
   * this sequence number */
  int32u  aru[NUM_SERVER_SLOTS];

  /* For each (i, j), I know that i has acknowledged (cumulatively or
   * regularly) having PO_Requests through [i][j] from j */
  int32u  cum_max_acked[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];

  int32u  cum_aru[NUM_SERVER_SLOTS];
  stdhash History[NUM_SERVER_SLOTS];
  int32u  max_num_sent_in_proof[NUM_SERVER_SLOTS];
  
  /* The last PO-ARU I've received from each server */
  po_aru_signed_message cum_acks[NUM_SERVER_SLOTS];

  /* Preorder sequence number, incremented each time I sent a Local
   * PO_Request*/
  int32u po_seq_num;

  /* PO-ARU number, incremented each time I send a Local PO-ARU */
  int32u po_aru_num;

  /* For each server i, I've executed preordered events through 
   * (i, white_line[i]) */
  int32u white_line[NUM_SERVER_SLOTS];

  /* Timers */
  util_stopwatch po_request_sw;
  util_stopwatch po_ack_sw;
  util_stopwatch po_aru_sw;
  util_stopwatch proof_matrix_sw;

  /* Local Token rate limiter */
  int32 tokens;
  util_stopwatch token_stopwatch;

  /* Queue of PO-Request and PO-Proof messages waiting to be sent */
  dll_struct po_request_dll;
  dll_struct proof_matrix_dll;

  /* If we try to execute a local commit but don't yet have all of
   * the PO-Requests that become eligible, we need to hold off on
   * executing.  When we hold off b/c of PO-Request (i, j), we'll
   * store a pointer to the ord_slot in Pending_Execution[i] --> j */
  stdhash Pending_Execution[NUM_SERVER_SLOTS];

  /* Map[i] stores local_recon slots for preorder ids (i, j) */
  stdhash Recon_History[NUM_SERVER_SLOTS];

  /* (i, j) = k means: I have sent a recon message to server i for a
   * po_request (j, k) */
  int32u Recon_Max_Sent[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];

} po_data_struct;

typedef struct dummy_po_slot {
  /* The preorder sequence number */
  int32u seq_num;           
  
  /* A copy of the request message */
  signed_message *po_request; 

  /* Tracks the acks received from each server */
  int32u ack_received[NUM_SERVER_SLOTS]; 
  int32u ack_count;
  
  /* Used to keep track of how many updates are packed into this po_request */
  int32u num_events;
} po_slot;

/* Ordering data structure slot */
typedef struct dummy_ord_slot {
  /* seq number of this slot */
  int32u seq_num;		
  int32u view;

  /* current pre prepare */
  int32u pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  int32u total_parts;
  int32u num_parts_collected;
  int32u collected_all_parts;
  int32u should_handle_complete_pre_prepare;
  complete_pre_prepare_message complete_pre_prepare;

  /* Flag: did we forward the Pre-Prepare part? */
  int32u forwarded_pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  int32u num_forwarded_parts;

  /* current prepares */
  signed_message* prepare[NUM_SERVER_SLOTS]; 
  int32u ordered;
  int32u bound;
  int32u executed;

  /* current commits */
  signed_message* commit[NUM_SERVER_SLOTS];        

  /* When a Prepare certificate is ready, we mark the flag here.  The
   * dispatcher sees this and sends a commit, then sets the flag so we 
   * only send the commit once. */
  int32u prepare_certificate_ready;
  int32u sent_commit;

  /* Flag to signal if a a commit certificate should be executed */
  int32u execute_commit;	

  /* Last prepare certificate */
  prepare_certificate_struct prepare_certificate;	
  
  /* Commit certificate */
  commit_certificate_struct commit_certificate;	

  /* If we commit the slot before we're ready to execute, this tells
   * us how many missing po-requests we need to collect before we can
   * execute. */
  int32u num_remaining_for_execution;

  /* Have we already reconciled on this slot? */
  int32u reconciled;

} ord_slot;

typedef struct dummy_ordering_data_struct {
  /* The local ARU. */
  int32u ARU;
  
  /* Number of events we've ordered */
  int32u events_ordered;

  /* The next sequence number to assign */
  int32u seq;

  /* The Ordering History, which stores ordering_slots */
  stdhash History;

  util_stopwatch pre_prepare_sw;

  /* To store ord slots that are globally ordered but not yet ready to
   * be globally executed. */
  stdhash Pending_Execution;

  int32u forwarding_white_line;
  int32u recon_white_line;

} ordering_data_struct;

typedef struct dummy_signature_data_struct {
  dll_struct pending_messages_dll;

  int32u seq_num;

  /* How many messages we've read without generating a signature.  If
   * this gets above a certain threshold, call the Sig signing
   * function immediately. */
  int32u num_consecutive_messages_read;

  sp_time sig_time;

} signature_data_struct;

/* This stores all of the server's state, including Preordering
 * and Ordering state. */
typedef struct dummy_server_data_struct {
  /* The view number.  For the tests, should always be 1. */
  int View;
  
  /* The Pre-Order data structure */
  po_data_struct PO;
  
  /* The Ordering data structure */
  ordering_data_struct ORD;

  signature_data_struct SIG;

} server_data_struct;
#endif
