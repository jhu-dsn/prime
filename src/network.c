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

#include <stdlib.h>
#include <string.h>
#include "sys/socket.h"
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <assert.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"
#include "objects.h"
#include "net_types.h"
#include "data_structs.h"
#include "network.h"
#include "utility.h"
#include "validate.h"
#include "apply.h"
#include "dispatcher.h"
#include "pre_order.h"
#include "tcp_wrapper.h"

#ifdef SET_USE_SPINES
#include "../spines/spines_lib.h"
#endif

#define UDP_SOURCE     1
#define SPINES_SOURCE  2
#define TCP_SOURCE     3

/* Global variables defined elsewhere */
extern network_variables   NET;
extern server_variables    VAR;
extern server_data_struct  DATA;
extern benchmark_struct    BENCH;

/* Local buffer for receiving the packet */
static sys_scatter srv_recv_scat;

/* Local Functions */
void NET_Client_Connection_Acceptor(int sd, int dummy, void *dummyp);
void NET_Throttle_Send             (int dummy, void* dummyp);
void NET_Send_Message(net_struct *n);
void Initialize_Listening_Socket(void);
void Initialize_UDP_Sockets(void);

/* Maximize the send and receive buffers.  Thanks to Nilo Rivera. */
int max_rcv_buff(int sk);
int max_snd_buff(int sk);

#ifdef SET_USE_SPINES
void Initialize_Spines(void);
#endif

void Init_Network(void) 
{
  int32u i;
#if THROTTLE_OUTGOING_MESSAGES
  sp_time t;
#endif

  /* Each server listens for incoming TCP connections from clients on
   * port PRIME_TCP_PORT */
  Initialize_Listening_Socket();

  Initialize_UDP_Sockets();

  /* Initialize the receiving scatters */
  srv_recv_scat.num_elements    = 1;
  srv_recv_scat.elements[0].len = sizeof(packet);
  srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(srv_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
  
#ifdef SET_USE_SPINES
  Initialize_Spines();
#endif

  /* Initialize the rest of the data structure */
  for(i = 0; i < 2; i++) {
    UTIL_DLL_Initialize(&NET.pending_messages_dll[i]);
    NET.tokens[i] = 0.0;
    UTIL_Stopwatch_Start(&NET.sw[i]);
  }

#if THROTTLE_OUTGOING_MESSAGES
  t.sec  = THROTTLE_SEND_SEC;
  t.usec = THROTTLE_SEND_USEC;
  E_queue(NET_Throttle_Send, 0, NULL, t);
#endif
}

void Initialize_Listening_Socket()
{
  struct sockaddr_in server_addr;
  long on = 1;

  if((NET.listen_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");
  
  if((setsockopt(NET.listen_sd, SOL_SOCKET, SO_REUSEADDR, &on,
		 sizeof(on))) < 0) {
    perror("setsockopt");
    exit(0);
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(PRIME_TCP_BASE_PORT+VAR.My_Server_ID);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if((bind(NET.listen_sd, (struct sockaddr *)&server_addr,
	   sizeof(server_addr))) < 0) {
    perror("bind");
    exit(0);
  }

  if((listen(NET.listen_sd, 50)) < 0) {
    perror("listen");
    exit(0);
  }

  /* Register the listening socket descriptor */
  E_attach_fd(NET.listen_sd, READ_FD, NET_Client_Connection_Acceptor, 
	      0, NULL, MEDIUM_PRIORITY);
}

void Initialize_UDP_Sockets()
{
  int32 ret;
  long off = 0;

  /* UDP Unicast */
  NET.Bounded_Port = PRIME_BOUNDED_SERVER_BASE_PORT + VAR.My_Server_ID;
  NET.Timely_Port  = PRIME_TIMELY_SERVER_BASE_PORT  + VAR.My_Server_ID;
  NET.Recon_Port   = PRIME_RECON_SERVER_BASE_PORT   + VAR.My_Server_ID;

  /* Bounded: Unicast */
  NET.Bounded_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
					NET.Bounded_Port, 0, 0);
  
  /* Timely: Unicast */
  NET.Timely_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
				       NET.Timely_Port, 0, 0);
  
  /* Reconciliation: Unicast */
  NET.Recon_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
				      NET.Recon_Port, 0, 0);

#ifndef SET_USE_SPINES
  /* Maximize the size of the buffers on each socket */
  max_rcv_buff(NET.Bounded_Channel);
  max_rcv_buff(NET.Timely_Channel);
  max_rcv_buff(NET.Recon_Channel);
  max_snd_buff(NET.Bounded_Channel);
  max_snd_buff(NET.Timely_Channel);
  max_snd_buff(NET.Recon_Channel);

  /* Attach each one to the event system */
  E_attach_fd(NET.Bounded_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 

  E_attach_fd(NET.Timely_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 

  E_attach_fd(NET.Recon_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 
#endif

  if(USE_IP_MULTICAST) {

#ifdef SET_USE_SPINES
    /* Use of IP Multicast is not consistent with using spines for
     * communication among servers. */
    Alarm(PRINT, "You are trying to use spines but the USE_IP_MULTICAST "
	  "configuration parameter is set.  Please set one or the other.\n");
    exit(0);
#endif

    if(THROTTLE_OUTGOING_MESSAGES) {
      /* IP Multicast also cannot be used with throttling */
      Alarm(PRINT, "You have both USE_IP_MULTICAST and "
	    "THROTTLE_OUTGOING_MESSAGES set.  Please set one or the other.\n");
      exit(0);
    }    

    /* Bounded traffic class: 225.2.1.1 
     * Timely  traffic class: 225.2.1.2 */
    NET.Bounded_Mcast_Address = 225 << 24 | 2 << 16 | 1 << 8 | 1;
    NET.Timely_Mcast_Address  = 225 << 24 | 2 << 16 | 1 << 8 | 2;

    Alarm(PRINT, "Setting my bounded mcast address to "IPF"\n", 
	  IP(NET.Bounded_Mcast_Address) );
    Alarm(PRINT, "Setting my timely  mcast address to "IPF"\n", 
	  IP(NET.Timely_Mcast_Address) );

    NET.Bounded_Mcast_Port = PRIME_BOUNDED_MCAST_PORT;
    NET.Timely_Mcast_Port  = PRIME_TIMELY_MCAST_PORT;

    NET.Bounded_Mcast_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
						NET.Bounded_Mcast_Port,
						NET.Bounded_Mcast_Address, 0);

    NET.Timely_Mcast_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
					       NET.Timely_Mcast_Port,
					       NET.Timely_Mcast_Address, 0);
    max_rcv_buff(NET.Bounded_Mcast_Channel);
    max_rcv_buff(NET.Timely_Mcast_Channel);
    
    /* If we're using multicast, don't receive your own messages */
    if((ret = setsockopt(NET.Bounded_Mcast_Channel, IPPROTO_IP, 
			 IP_MULTICAST_LOOP, (void *)&off, 1)) < 0) {
      perror("setsockopt");
      exit(0);
    }
    
    /* If we're using multicast, don't receive your own messages */
    if((ret = setsockopt(NET.Timely_Mcast_Channel, IPPROTO_IP, 
			 IP_MULTICAST_LOOP, (void *)&off, 1)) < 0) {
      perror("setsockopt");
      exit(0);
    }

    E_attach_fd(NET.Timely_Mcast_Channel, READ_FD, Net_Srv_Recv, UDP_SOURCE, 
		NULL, MEDIUM_PRIORITY);

    E_attach_fd(NET.Bounded_Mcast_Channel, READ_FD, Net_Srv_Recv, UDP_SOURCE, 
		NULL, MEDIUM_PRIORITY);
  }
}

/* Attempts to send timely and bounded messages */
void NET_Throttle_Send(int dummy, void *dummyp)
{
  int32u i, bits, bytes;
  signed_message *mess;
  double time, add;
  net_struct *n;
  sp_time t;

  /* First send timely messages, then bounded ones */
  for(i = 0; i < NUM_TRAFFIC_CLASSES; i++) {

    while(!UTIL_DLL_Is_Empty(&NET.pending_messages_dll[i])) {

      UTIL_DLL_Set_Begin(&NET.pending_messages_dll[i]);
      
      UTIL_Stopwatch_Stop(&NET.sw[i]);
      time = UTIL_Stopwatch_Elapsed(&NET.sw[i]);
      UTIL_Stopwatch_Start(&NET.sw[i]);

      /* Compute number of tokens to add based on whether we are using erasure
       * codes, are emulated, and are dealing with timely or asynchronous
       * messages. */
      if(i == TIMELY_TRAFFIC_CLASS)
	add = (double) MAX_OUTGOING_BANDWIDTH_TIMELY * time;
      else if(i == BOUNDED_TRAFFIC_CLASS)
	add = (double) MAX_OUTGOING_BANDWIDTH_BOUNDED * time;
      else if(i == RECON_TRAFFIC_CLASS)
      	add = (double) MAX_OUTGOING_BANDWIDTH_RECON * time;
      else
	Alarm(EXIT, "Throttling unknown traffic class: %d\n", i);

      NET.tokens[i] += add;

      if(NET.tokens[i] > MAX_TOKENS)
	NET.tokens[i] = MAX_TOKENS;

      n    = UTIL_DLL_Front_Message(&NET.pending_messages_dll[i]);
      mess = n->mess;

      bytes = UTIL_Message_Size(mess);
#ifdef SET_USE_SPINES
      bytes += 16 + 24;
#endif
      bits = bytes * 8;

      if(NET.tokens[i] < bits) {
	Alarm(DEBUG, "Not enough tokens to send: %f %d, timely = %d\n",
	      NET.tokens[i], bits, i);
	break;
      }
      
      NET.tokens[i] -= bits;

      NET_Send_Message(n);
      Alarm(DEBUG, "Num remaining = %d\n", n->num_remaining_destinations);
      
      if(n->num_remaining_destinations == 0) {
	dec_ref_cnt(n->mess);
	UTIL_DLL_Pop_Front(&NET.pending_messages_dll[i]);
      }
    }
  }

  t.sec  = THROTTLE_SEND_SEC;
  t.usec = THROTTLE_SEND_USEC;
  E_queue(NET_Throttle_Send, 0, NULL, t);
}

void NET_Send_Message(net_struct *n)
{
  int32u i;

  assert(n->mess);

  /* We can either send to the destination servers sequentially, or we
   * can pick one that still needs the message at random. */
  if(RANDOMIZE_SENDING) {
    while(1) {
      i = (rand() % NUM_SERVERS) + 1;
      if(n->destinations[i] == 1)
	break;
    }
  }
  else {
    for(i = 1; i <= NUM_SERVERS; i++)
      if(n->destinations[i] == 1)
	break;
  }

  assert(i != VAR.My_Server_ID);
  assert(i <= NUM_SERVERS);

  /* We've decided to send to server i */
  UTIL_Send_To_Server(n->mess, i);

  n->destinations[i] = 0;
  n->num_remaining_destinations--;
}

#ifdef SET_USE_SPINES
void Initialize_Spines()
{
  channel spines_recv_sk = -1;
  struct sockaddr_in spines_addr, my_addr;
  int ret, priority;
  int16u protocol;

  memset(&spines_addr, 0, sizeof(spines_addr));  
  memset(&my_addr, 0, sizeof(my_addr));  
 
  spines_addr.sin_family = AF_INET;
  spines_addr.sin_port   = htons(SPINES_PORT);
  spines_addr.sin_addr.s_addr = 
    htonl(UTIL_Get_Server_Spines_Address(VAR.My_Server_ID));
    
  Alarm(DEBUG, "%d Init Spines... "IPF"\n", VAR.My_Server_ID, 
	IP(ntohl(spines_addr.sin_addr.s_addr)));
  
  /* Connect to spines */
  // x | (y << 8)
  // x = {0,1,2,3,4,5,6,7,8}
  //   - 0 best effort
  //   - 1 reliable
  //   - 8 intrusion tolerant
  // y = {0,1,2}
  //   - shortest path routing
  //   - priority flooding
  //   - reliable flooding
  // Intusion-tolerant Spines: x = 8, y = 2
  // Spines 4.0: x = 1, y = 0 
  protocol = 8 | (2 << 8);
  spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
				 (struct sockaddr *)&spines_addr);

  if(spines_recv_sk == -1) {
    Alarm(PRINT, "%d Could not connect to Spines daemon.\n", VAR.My_Server_ID );
    exit(0);
  } 

  /* Set the buffer size of the socket */
  Alarm(PRINT, "Spines channel: ");
  max_rcv_buff(spines_recv_sk);
  max_snd_buff(spines_recv_sk);

  /* Bind to my unique port */  
  my_addr.sin_addr.s_addr = htonl(UTIL_Get_Server_Address(VAR.My_Server_ID));
  my_addr.sin_port        = htons(PRIME_SPINES_SERVER_BASE_PORT + 
				  VAR.My_Server_ID);
      
  ret = spines_bind(spines_recv_sk, (struct sockaddr *)&my_addr,
		    sizeof(struct sockaddr_in));
  if(ret == -1) {
    Alarm(PRINT, "Could not bind on Spines daemon.\n");
    exit(1);
  }

  /* Register the socket with the event system */
  priority = MEDIUM_PRIORITY;
  E_attach_fd(spines_recv_sk, READ_FD, Net_Srv_Recv, SPINES_SOURCE,
	      NULL, priority ); //MEDIUM_PRIORITY );
  
  NET.Spines_Channel = spines_recv_sk;

  Alarm(PRINT, "Successfully connected to Spines!\n");
}
#endif

void Net_Srv_Recv(channel sk, int source, void *dummy_p) 
{
  int received_bytes, ret;
  signed_message *mess;

  /* Read the packet from the socket */
  if(source == UDP_SOURCE)
    received_bytes = DL_recv(sk, &srv_recv_scat);
#ifdef SET_USE_SPINES
  else if(source == SPINES_SOURCE) {
    received_bytes = spines_recvfrom(sk, srv_recv_scat.elements[0].buf, 
				     PRIME_MAX_PACKET_SIZE, 0, NULL, 0);
    if(received_bytes <= 0) {
      Alarm(PRINT, "Error: Lost connection to spines...\n");
      exit(0);
    }
  }
#endif
  else if(source == TCP_SOURCE) {
    ret = TCP_Read(sk, srv_recv_scat.elements[0].buf, 
		   sizeof(signed_update_message));
    if(ret <= 0) {
      perror("read");
      close(sk);
      E_detach_fd(sk, READ_FD);
      /* TODO: I should keep track of which client this is for and 
       * set the corresponding entry in NET.client_sd[] back to 0. */
      return;
    }
    else
      received_bytes = sizeof(signed_update_message);
  } 
  else {
    Alarm(EXIT, "Unexpected packet source!\n");
    return;
  }

  /* Process the packet */
  mess = (signed_message*)srv_recv_scat.elements[0].buf;

  if(source == TCP_SOURCE) {
    assert(mess->type == UPDATE);

    /* Store the socket so we know how to send a response */
    if(NET.client_sd[mess->machine_id] == 0)
      NET.client_sd[mess->machine_id] = sk;
  }

  /* 1) Validate the Packet.  If the message does not validate, drop it. */
  if (!VAL_Validate_Message(mess, received_bytes)) {
    Alarm(DEBUG, "VALIDATE FAILED for type %d from server %d\n", mess->type, mess->machine_id);
    return;
  }

  /* No Conflict, Apply the message to our data structures. */
  APPLY_Message_To_Data_Structs(mess);
  /* Now dispatch the mesage so that is will be processed by the
   * appropriate protocol */
  DIS_Dispatch_Message(mess);
  /* The following checks to see if the packet has been stored and, if so, it
   * allocates a new packet for the next incoming message. */
  if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
    dec_ref_cnt(srv_recv_scat.elements[0].buf);
    
    if((srv_recv_scat.elements[0].buf = 
	(char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
      Alarm(EXIT, "Net_Srv_Recv: Could not allocate packet body obj\n");
    }
  } 
}

void NET_Client_Connection_Acceptor(int sd, int dummy, void *dummyp)
{
  struct sockaddr_in client_addr;
  socklen_t len;
  int connfd;

  len    = sizeof(client_addr);
  if((connfd = accept(sd, (struct sockaddr *)&client_addr, &len)) < 0) {
    perror("accept");
    exit(0);
  }
  Alarm(PRINT, "Accepted a client connection!\n");
  
  E_attach_fd(connfd, READ_FD, Net_Srv_Recv, TCP_SOURCE, NULL, 
	      MEDIUM_PRIORITY);
}

int max_rcv_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;
  
  for(i=10; i <= 300000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
    if(val < i*1024 )
      break;
  }
  return(1024*(i-5));

}

int max_snd_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 300000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
    if(val < i*1024)
      break;
  }
  return(1024*(i-5));
}
