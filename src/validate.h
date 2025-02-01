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

/* The validation code (validate.h and validate.c) makes sure that messages are
 * authentic by verifying signatures and makes sure that the messages have the
 * expected lengths based on what type they are. It also insures that any
 * specified sender (client, server, or site) is valid. */

#ifndef PRIME_VALIDATE_H
#define PRIME_VALIDATE_H

#include "arch.h"
#include "data_structs.h"

#define VAL_TYPE_INVALID       1
#define VAL_SIG_TYPE_SERVER    2
#define VAL_SIG_TYPE_SITE      3
#define VAL_SIG_TYPE_CLIENT    4
#define VAL_SIG_TYPE_UNSIGNED  5

/* Validation Functions */

/* Public */
int32u VAL_Validate_Message( signed_message *message, int32u num_bytes ); 
int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature); 
int32u VAL_Validate_Report	(report_message *report,   int32u num_bytes);
int32u VAL_Validate_PC_Set	(pc_set_message *pc_set,   int32u num_bytes);

#endif 
