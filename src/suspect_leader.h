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
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *
 * Copyright (c) 2008 - 2014
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Prime research was provided by the Defense Advanced
 * Research Projects Agency (DARPA) and The National Security Agency (NSA).
 * Prime is not necessarily endorsed by DARPA or the NSA.
 *
 */

#ifndef PRIME_SUSPECT_LEADER_H
#define PRIME_SUSPECT_LEADER_H

#include "packets.h"
#include "data_structs.h"

void SUSPECT_Dispatcher (signed_message *mess);

void SUSPECT_Initialize_Data_Structure (void);
void SUSPECT_Initialize_Upon_View_Change(void);

void SUSPECT_Send_RTT_Ping(void);
void SUSPECT_Send_RTT_Pong(int32u server_id, int32u seq_num);
void SUSPECT_Send_RTT_Measure(int32u server_id, double rtt);
void SUSPECT_Send_TAT_Measure(void);
void SUSPECT_Send_TAT_UB(double alpha);
void SUSPECT_Send_New_Leader(void);
void SUSPECT_Send_New_Leader_Proof(void);

void SUSPECT_Start_Measure_TAT(void);
void SUSPECT_Stop_Measure_TAT(void);

void SUSPECT_Cleanup(void);

#endif
