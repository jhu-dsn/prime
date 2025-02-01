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

#ifndef PRIME_VIEW_CHANGE_H
#define PRIME_VIEW_CHANGE_H

#include "packets.h"
#include "data_structs.h"

void VIEW_Start_View_Change(void);

void VIEW_Dispatcher (signed_message *mess);

void VIEW_Initialize_Data_Structure (void);

void VIEW_Send_Report(void);
void VIEW_Send_PC_Set(void);
void VIEW_Send_VC_List(void);
void VIEW_Send_VC_Partial_Sig(int32u ids);
void VIEW_Send_VC_Proof(int32u view, int32u ids, int32u startSeq, byte *sig);
void VIEW_Send_Replay(vc_proof_message *proof);
void VIEW_Send_Replay_Prepare(void);
void VIEW_Send_Replay_Commit(void);

void   VIEW_Check_Complete_State();

void VIEW_Cleanup(void);

#endif
