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

#ifndef PRIME_RELIABLE_BROADCAST_H
#define PRIME_RELIABLE_BROADCAST_H

#include "packets.h"
#include "data_structs.h"

void RELIABLE_Broadcast_Reliably(signed_message *mess);

void RELIABLE_Dispatcher (signed_message *mess);

void RELIABLE_Initialize_Data_Structure (void);
void RELIABLE_Initialize_Upon_View_Change (void);

void RELIABLE_Send_RB_Init(signed_message *mess);
void RELIABLE_Send_RB_Echo(signed_message *mess);
void RELIABLE_Send_RB_Ready(signed_message *mess);

void RELIABLE_Cleanup(void);

#endif
