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

/* Message validation functions. These functions check to make sure messages
 * came from the server or site that should have sent them and check to make
 * sure that the lengths are correct. */

#include "util/alarm.h"
#include "validate.h"
#include "data_structs.h"
#include "error_wrapper.h"
#include "merkle.h"
#include "openssl_rsa.h"
#include "utility.h"
#include "packets.h"

extern server_variables VAR;

int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature); 
int32u VAL_Signature_Type         (int32u message_type); 
int32u VAL_Validate_Sender        (int32u sig_type, int32u sender_id); 
int32u VAL_Is_Valid_Signature     (int32u sig_type, int32u sender_id, 
				   int32u site_id, signed_message *mess);

int32u VAL_Validate_Update    (update_message *update, int32u num_bytes); 
int32u VAL_Validate_PO_Request(po_request_message *po_request,
			       int32u num_bytes);
int32u VAL_Validate_PO_Ack      (po_ack_message *po_ack,   int32u num_bytes);
int32u VAL_Validate_PO_ARU      (po_aru_message *po_aru,   int32u num_bytes);
int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes);
int32u VAL_Validate_Pre_Prepare (pre_prepare_message *pp,  int32u num_bytes);
int32u VAL_Validate_Prepare     (prepare_message *prepare, int32u num_bytes);
int32u VAL_Validate_Commit      (commit_message *commit,   int32u num_bytes);

/* Determine if a message from the network is valid. */
int32u VAL_Validate_Message(signed_message *message, int32u num_bytes) 
{
  byte *content;
  int32u num_content_bytes;
  int32u ret, i;

  /* Since we use Merkle trees, all messages except client updates
   * need to be Merkle-tree verified. */

  if(message->type == UPDATE && (CLIENTS_SIGN_UPDATES == 0))
    return 1;

  /* Emulates checking signature of each event contained in the PO Request */
  if(message->type == PO_REQUEST && CLIENTS_SIGN_UPDATES) {
    po_request_message *r = (po_request_message *)(message+1);
    ret = 1;
    for(i = 0; i < r->num_events; i++)
      ret = MT_Verify(message);
    return ret;
  }

  ret = MT_Verify(message);
  if(ret == 0) {
    Alarm(PRINT, "MT_Verify returned 0 on message from machine %d type %d "
	  "len %d, total len %d\n", message->machine_id, message->type, 
	  message->len, UTIL_Message_Size(message));
    return 0;
  }
  else {
    return 1;
  }

  /* TODO: Validation functions should be called but they currently are not. */
  

  /* This is a signed message */
  if (!VAL_Validate_Signed_Message(message, num_bytes, 1)) {
    Alarm(VALID_PRINT, "Validate signed message failed.\n");
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }

  if (num_bytes < sizeof(signed_message)) {
    /* Safety check -- should be impossible */
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }
  
  content = (byte*)(message + 1);
  num_content_bytes = num_bytes - sizeof(signed_message); /* always >= 0 */

  switch (message->type) {

  case UPDATE:
    if((!VAL_Validate_Update((update_message *)(content), num_content_bytes))){
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_REQUEST:
    if((!VAL_Validate_PO_Request((po_request_message *)content,
				 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PO_ACK:
    if((!VAL_Validate_PO_Ack((po_ack_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_ARU:
    if((!VAL_Validate_PO_ARU((po_aru_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PROOF_MATRIX:
    if((!VAL_Validate_Proof_Matrix((proof_matrix_message *)content,
				   num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PRE_PREPARE:
    if((!VAL_Validate_Pre_Prepare((pre_prepare_message *)content,
				  num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PREPARE:
    if((!VAL_Validate_Prepare((prepare_message *)content,
			      num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case COMMIT:
    if((!VAL_Validate_Commit((commit_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  default:
    Alarm(PRINT, "Not yet checking message type %d!\n", message->type);
  }
  
  return 1;
}

/* Determine if a signed message is valid. */
int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature) 
{
  int32u sig_type;
  int32u sender_id;

  if (num_bytes < (sizeof(signed_message))) {
    VALIDATE_FAILURE("Num bytes < sizeof(signed_message)");
    return 0;
  }
   
  if (num_bytes != mess->len + sizeof(signed_message) + 
      MT_Digests_(mess->mt_num) * DIGEST_SIZE) {
    Alarm(PRINT, "num_bytes = %d, signed_message = %d, mess->len = %d, "
	  "digests = %d\n",
	  num_bytes, sizeof(signed_message), mess->len, 
	  MT_Digests_(mess->mt_num));
    VALIDATE_FAILURE("num_bytes != mess->len + sizeof(signed_message)");
    return 0;
  }

  sig_type = VAL_Signature_Type( mess->type );

  if (sig_type == VAL_TYPE_INVALID) {
    VALIDATE_FAILURE("Sig Type invalid");
    return 0;
  }

  /* TODO: Should probably check the sender */
  if(sig_type == VAL_SIG_TYPE_UNSIGNED)
    return 1;

  if (sig_type == VAL_SIG_TYPE_SERVER ||
      sig_type == VAL_SIG_TYPE_CLIENT) {
    sender_id = mess->machine_id;
  } else {
    /* threshold signed */
    sender_id = mess->site_id;
  }
  
  if (!VAL_Validate_Sender(sig_type, sender_id)) {
    VALIDATE_FAILURE("Invalid sender");
    return 0;
  }
  
  if (!VAL_Is_Valid_Signature(sig_type, sender_id, mess->site_id, mess)) {
    VALIDATE_FAILURE("Invalid signature");
    return 0;
  }
    
  return 1; /* Passed all checks */
}

/* Determine if the message type is valid and if so return which type of
 * signature is on the message, a client signature, a server signature, or a
 * threshold signature. 
 * 
 * returns: VAL_SIG_TYPE_SERVER, VAL_SIG_TYPE_CLIENT, VAL_SIG_TYPE_SITE, or
 * VAL_TYPE_INVALID */
int32u VAL_Signature_Type(int32u message_type) 
{
  int sig_type = VAL_TYPE_INVALID;
  
  /* Return the type of the signature based on the type of the message. If
   * the type is not found, then return TYPE_INVALID */

  switch(message_type) {

  case UPDATE:
    sig_type = VAL_SIG_TYPE_CLIENT;
    break;
  
  case PO_REQUEST:
  case PO_ACK:
  case PO_ARU:
  case PROOF_MATRIX:
  case RECON:
  case PRE_PREPARE:
  case PREPARE:
  case COMMIT:
    sig_type = VAL_SIG_TYPE_SERVER;
    break;
  }

  return sig_type;
} 

/* Determine if the sender is valid depending on the specified signature type.
 * 
 * return: 1 if sender is valid, 0 if sender is not valid */
int32u VAL_Validate_Sender(int32u sig_type, int32u sender_id) 
{
  if (sender_id < 1) 
    return 0;

  if (sig_type == VAL_SIG_TYPE_SERVER && sender_id <= NUM_SERVERS) {
    return 1;
  } 
    
  if (sig_type == VAL_SIG_TYPE_CLIENT &&
      sender_id <= NUM_CLIENTS) {
    return 1;
  }	

  return 0;
}

/* Determine if the signature is valid. Assume that the lengths of the message
 * is okay. */
int32u VAL_Is_Valid_Signature(int32u sig_type, int32u sender_id, 
			      int32u site_id, signed_message *mess) 
{
  int32 ret;
  
  if (sig_type == VAL_SIG_TYPE_SERVER) {
    /* Check an RSA signature using openssl. A server sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_SERVER
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Server Failed %d %d\n",
	    mess->type, mess->machine_id);
    return ret; 
  }
   
  if (sig_type == VAL_SIG_TYPE_CLIENT) {
    /* Check an RSA signature using openssl. A client sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_CLIENT
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Client Failed %d\n", mess->type);
    return ret; 
  }
  
  return 0;
}

/* Determine if an update is valid */
int32u VAL_Validate_Update(update_message *update, int32u num_bytes) 
{
  
  /* Check to determine if the update is valid. We have already checked to
   * see if the signature verified. We only need to make sure that the packet
   * is large enough for the timestamp. */
  
  if (num_bytes < (sizeof(update_message))) {
    VALIDATE_FAILURE("");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_PO_Request(po_request_message *po_request, int32u num_bytes)
{
  signed_message *mess;
  char *p;
  int32u i;
  int32u wa_bytes;

  if (num_bytes < (sizeof(po_request_message))) {
    VALIDATE_FAILURE("Local PO-Request bad size");
    return 0;
  }
  
  /* This is the start of the events contained in the PO-Request */
  p = (char *)(po_request + 1);

  for(i = 0; i < po_request->num_events; i++) {
    mess = (signed_message *)p;
    
    wa_bytes = 0;

    if(!VAL_Validate_Message(mess, 
			     mess->len + sizeof(signed_message) + wa_bytes)) {
      Alarm(PRINT, "Event %d of PO-Request invalid\n", i);
      VALIDATE_FAILURE("Foo");
      return 0;
    }
    else {
      p += mess->len + sizeof(signed_message) + wa_bytes;
    }
  }
  
  return 1;
} 

int32u VAL_Validate_PO_Ack(po_ack_message *po_ack, int32u num_bytes)
{
  int32u expected_num_bytes;

  if(num_bytes < sizeof(po_ack_message)) {
    VALIDATE_FAILURE("PO-Ack wrong size");
    return 0;
  }

  expected_num_bytes = (sizeof(po_ack_message) +
			(po_ack->num_ack_parts * sizeof (po_ack_part)));

  if(num_bytes != expected_num_bytes) {
    VALIDATE_FAILURE("PO-Ack wrong expected bytes.");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_PO_ARU(po_aru_message *po_aru, int32u num_bytes)
{
  if (num_bytes != (sizeof(po_aru_message))) {
    VALIDATE_FAILURE("PO_ARU bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes)
{
  if(num_bytes != (sizeof(proof_matrix_message))) {
    VALIDATE_FAILURE("proof_matrix wrong size");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_Pre_Prepare(pre_prepare_message *pp, int32u num_bytes)
{
  Alarm(DEBUG, "VAL_Validate_Pre_Prepare\n");

  if(pp->seq_num < 0) {
    VALIDATE_FAILURE("Pre-Prepare bad seq");
    return 0;
  }

  if(num_bytes != sizeof(pre_prepare_message)) {
    VALIDATE_FAILURE("Pre-Prepare bad size");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_Prepare(prepare_message *prepare, int32u num_bytes)
{
  if(num_bytes != sizeof(prepare_message)) {
    VALIDATE_FAILURE("Prepare, bad size");
    return 0;
  }
  
  if(prepare->seq_num < 1) {
    VALIDATE_FAILURE("Prepare, bad seq");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_Commit(commit_message *commit, int32u num_bytes)
{
  if(num_bytes != sizeof(commit_message)) {
    VALIDATE_FAILURE("Commit: bad size");
    return 0;
  }

  if(commit->seq_num < 1) {
    VALIDATE_FAILURE("Commit: Bad seq");
    return 0;
  }
  
  return 1;
}
