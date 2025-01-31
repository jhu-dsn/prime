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

#ifndef PRIME_PACKETS_H
#define PRIME_PACKETS_H

#include "util/arch.h"
#include "util/sp_events.h"
#include "def.h"
#include "openssl_rsa.h"
#include "util_dll.h"

enum packet_types {DUMMY, 
		   PO_REQUEST,  PO_ACK,  PO_ARU, PROOF_MATRIX,
		   PRE_PREPARE, PREPARE, COMMIT, RECON,
		   UPDATE, CLIENT_RESPONSE};

typedef byte packet_body[PRIME_MAX_PACKET_SIZE];

typedef struct dummy_signed_message {
  byte sig[SIGNATURE_SIZE];
  int16u mt_num;
  int16u mt_index;

  int32u site_id;
  int32u machine_id; 
  
  int32u len;        /* length of the content */
  int32u type;       /* type of the message */
  
  int32u seq_num;

  /* Content of message follows */
} signed_message;

/* Update content. Note that an update message has almost the same
 * structure as a signed message. It has an additional content
 * structure that contains the time stamp. Therefore, an update
 * message is actually a signed_message with content of update_content
 * and the actual update data */
typedef struct dummy_update_message {
  int32u server_id;
  int32  address;
  int16  port;
  int32u time_stamp;
  /* the update content follows */
} update_message;

typedef struct dummy_signed_update_message {
  signed_message header;
  update_message update;
  byte update_contents[UPDATE_SIZE];
} signed_update_message;

typedef struct dummy_po_request {
  int32u seq_num;          
  int32u num_events;
  /* Event(s) follows */
} po_request_message;

/* Structure for batching acks */
typedef struct dummy_po_ack_part {
  int32u originator;                /* originating entity (server) */
  int32u seq_num;                   /* seq number                  */
  byte digest[DIGEST_SIZE];         /* a digest of the update      */
} po_ack_part;

typedef struct dummy_po_ack_message {
    int32u num_ack_parts;             /* Number of Acks */
    /* a list of po_ack_parts follows */
} po_ack_message;

/* Messages for Pre-Ordering */
typedef struct dummy_po_aru_message {
  int32u num;
  /* Cumulative ack for each server */
  int32u ack_for_server[NUM_SERVERS]; 
} po_aru_message;

/* a struct containing pre-order proof messages */
typedef struct dummy_po_cum_ack_signed_message {
  signed_message header;
  po_aru_message cum_ack;
} po_aru_signed_message;

typedef struct dummy_proof_matrix_message {
  int32u num_acks_in_this_message;

  /* The content follows: some number of po_aru_signed_messages */
} proof_matrix_message;

typedef struct dummy_pre_prepare_message {
  /* Ordering sequence number */
  int32u seq_num;          
  
  /* View number */
  int32u view;

  int16u part_num;
  int16u total_parts;
  int32u num_acks_in_this_message;

} pre_prepare_message;

/* Structure of a Prepare Message */
typedef struct dummy_prepare_message {
  int32u seq_num;              /* seq number                            */
  int32u view;                 /* the view number                       */
  byte   digest[DIGEST_SIZE];  /* a digest of whatever is being ordered */
} prepare_message;

/* Structure of a Commit Message */
typedef struct dummy_commit_message {
  int32u seq_num;                      /* seq number */
  int32u view;
  byte digest[DIGEST_SIZE];   /* a digest of the content */
} commit_message;

typedef struct dummy_complete_pre_prepare_message {
  int32u seq_num;
  int32u view;

  po_aru_signed_message cum_acks[NUM_SERVERS];
} complete_pre_prepare_message;

typedef struct dummy_client_response_message {
  int32u machine_id;
  int32u seq_num;
} client_response_message;

typedef struct dummy_erasure_part {

  /* Length of the message this part is encoding, in bytes.  The receiver
   * can compute the length of the part based on this value. */
  int32u mess_len; 

  /* The part follows, in the form <index, part> */
} erasure_part;

typedef struct dummy_recon_message {

  /* The number of parts that follow, each one with a recon_part_header to
   * indicate the preorder identifier (i, j) for the message encoded. */
  int32u num_parts;

} recon_message;

/* A Prepare certificate consists of 1 Pre-Prepare and 2f Prepares */
typedef struct dummy_prepare_certificate {
  complete_pre_prepare_message pre_prepare;
  signed_message* prepare[NUM_SERVER_SLOTS]; 
} prepare_certificate_struct;

/* A Commit certificate consists of 2f+1 Commits */
typedef struct dummy_commit_certificate {
    //byte update_digest[DIGEST_SIZE];    /* The update digest */
    signed_message* commit[NUM_SERVER_SLOTS]; /* The set of prepares */
} commit_certificate_struct;

signed_message* PRE_ORDER_Construct_PO_Request  (void);
signed_message* PRE_ORDER_Construct_PO_Ack      (int32u *more_to_ack);
signed_message* PRE_ORDER_Construct_PO_ARU      (void);
void PRE_ORDER_Construct_Proof_Matrix(signed_message **mset, 
				      int32u *num_parts);

void ORDER_Construct_Pre_Prepare(signed_message **mset, int32u *num_parts);
signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp);
signed_message* ORDER_Construct_Commit (complete_pre_prepare_message *pp);
signed_message* ORDER_Construct_Client_Response(int32u client_id, 
						int32u seq_num);

signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
							int32u *more_to_encode);
#endif
