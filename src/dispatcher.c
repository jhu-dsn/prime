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

/* The dispatcher sends messages, based on type, to one of the protocols. All
 * messages are of type signed_message. */

#include "dispatcher.h"
#include "util/arch.h"
#include "util/alarm.h"
#include "packets.h"
#include "pre_order.h"
#include "order.h"

/* Protocol types */
#define PROT_INVALID       0
#define PROT_PRE_ORDER     1
#define PROT_ORDER         2

int32u DIS_Classify_Message(signed_message *mess);

void DIS_Dispatch_Message(signed_message *mess) 
{
  int32u prot_type;
  
  prot_type = DIS_Classify_Message(mess);

  switch(prot_type) {

  case PROT_PRE_ORDER:
    PRE_ORDER_Dispatcher(mess);
    break;
    
  case PROT_ORDER:
    ORDER_Dispatcher(mess);
    break;

  default:
    Alarm(EXIT, "Unexpected protocol type in Dispatch_Message!\n");
    break;
  }
}

/* Dispatch Code */
int32u DIS_Classify_Message(signed_message *mess) 
{

  switch(mess->type) {

  case UPDATE:
  case PO_REQUEST:
  case PO_ACK:
  case PO_ARU:
  case PROOF_MATRIX:
  case RECON:
    return PROT_PRE_ORDER;
    
  case PRE_PREPARE:
  case PREPARE:
  case COMMIT:
    return PROT_ORDER;

  default:
    Alarm(EXIT, "Unable to classify message type %d!\n", mess->type);
  }

  return PROT_INVALID;
}
