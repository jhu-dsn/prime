*************************************
* Contents:
*    Prime Overview and Instructions
*    Software Dependencies
*    Configuration
*    Compiling
*    Running
*    Output Files
*    Erasure Codes
*    Prime Checklist
*************************************

***********************************
* Prime Overview and Instructions *
***********************************
Prime is a Byzantine fault-tolerant state machine replication system.
The system consists of (1) a collection of servers providing the
replicated service and (2) one or more clients that use the provided
service by communicating with the servers.  The system maintains
correctness as long as no more than f out of 3f+1 servers are
Byzantine.

This implementation is based on the protocol described in:

Y. Amir, B. Coan, J. Kirsch, J. Lane. Byzantine Replication Under
Attack.  In Proceedings of the 38th IEEE/IFIP International Conference
on Dependable Systems and Networks (DSN 2008), Anchorage, Alaska, June
2008, pp. 197-206.

The current release is intended to be used to benchmark the protocol
in various configurations (LAN, WAN, emulated WAN). It can also be
used to test the performance of Prime under certain types of attacks.
Specifically, the code can be instrumented (by setting a flag) so that 
the leader attempts to slow down the performance by causing as much 
delay as possible without being suspected. The code can also be
instrumented (by setting a flag) so that faulty servers try to cause
the correct servers to undergo as much reconciliation as possible
(i.e., to recover missing Preorder Requests).

The current release also supports proactive recovery and implements the 
state transfer protocol that prioritizes bandwidth usage over low latency 
described in:

M. Platania, D. Obenshain, T. Tantillo, R. Sharma, Y. Amir. Towards a
Practical Survivable Intrusion Tolerant Replication System. In Proceedings 
of the 33th IEEE/IFIP International Sysmposium on Reliable Distributed Systems 
(SRDS 2014), Nara, Japan, October 2014.

Prime servers can be periodically rejuvenated to clean the system from 
potentially undetected intrusions. After rejuvenation, a Prime server 
validates the contents of the state on the disk with the help of other 
correct replicas and recovers a clean copy of the state if necessary. 
Subsequently, the rejuvenated replica collects all the client updates 
necessary to catch up and resume the execution. The state and update 
transfer protocols are guaranteed to meet Safety at any time because 
they are coordinated by a quorum of correct replicas.

By default the proactive recovery protocol is enabled. It can be turned 
off by setting the flag RECOVERY to false in src/def.h.

**************************
* Software Dependencies: *
**************************
Prime uses the OpenSSL cryptographic library.  OpenSSL can be
downloaded from www.openssl.org.  The Makefile is set up to
dynamically link to to OpenSSL.  If necessary, you can modify the
Makefile to statically link to the library libcrypto.a.

Prime can be configured to make use of Spines, an overlay network
developed at Johns Hopkins (see http://spines.org).  This can be
useful for testing wide-area topologies and placing bandwidth and
latency constraints on the links between servers.  By default, the
system is set up not to use Spines.  In order to use Spines, download
and compile it, and place it at Prime/spines.  Then uncomment the
two lines in src/Makefile beginning with SPINES and SPINES_LIB.

******************
* Configuration: *
******************
The bin directory contains a sample address configuration file
(address.config), which tells the servers the IP addresses of all 
servers based on server id.  The file contains a line for each
server with the following format:

   server_id ip_address

The server_id is a number from 1 to the number of servers in the
system.  The ip_address is a standard dotted ipv4 address.

NOTE: The parameters in src/def.h must be written to match the address
configuration file (i.e., if NUM_SERVERS is set to 4, then there must
be an entry for each of the four servers in the bin/address.config
file).

Prime contains many configurable parameters; the code must be
recompiled to change these parameters.  The parameters are contained
in src/def.h.  Please refer to this file for details.  For reference,
the file is organized as follows:

   a. System-wide Configuration Settings
   b. Networking Settings 
   c. Cryptography Settings
   d. Throttling Settings (to control how much bandwidth is used)
   e. Periodic Sending Settings (to control message flow at certain steps)
   f. Attack Settings 

**************
* Compiling: *
**************
Enter the libspread-util folder and type ./configure and then make
to build the libraries.
Prime can be compiled by typing make in the src directory. Three
executables will be generated and stored in the bin directory.
The programs are gen_keys, server and client.

***********
* Running *
***********
The following assumes that you have successfully compiled the server and client
and carried out the necessary configuration steps discussed above. The servers
can be run as follows:

First make sure you are in the bin directory.

The gen_keys program must be run first:

./gen_keys

This generate RSA keys for the servers and clients.  The keys are
stored in bin/keys.  The server and client programs must read the keys
from the bin/keys directory.  We assume that in a secure deployment the
private keys are accessible only to the server to which they belong.
 
Then, the server can be run as follows:

./server -i SERVER_ID

where SERVER_ID denotes an integer from 1 to the number of servers in
the system.

The client can be run like this:

./client -l IP_ADDRESS -i CLIENT_ID [-s SERVER_ID] 

The first two arguments are required.  IP_ADDRESS denotes the IP
address of the client program, and CLIENT_ID denotes an integer from 1
to the maximum number of clients in the system.  If no other arguments
are specified, then the client will send each update to a
randomly-chosen server (note that this assumes all servers are
running).  When the "-s" option is used, the client will send its
updates only to the specified server.  One or more clients can be run.

A single client process can be configured to emulate the behavior of
many clients.  This can be achieved by setting the
NUM_CLIENTS_TO_EMULATE parameter in src/client.c and recompiling.  A
client process acts like a single client by default.

****************
* Output files *
****************
Prime can output several different types of files, which we now
describe.

STATE_MACHINE Output: Each server outputs a file
bin/state_machine_out.SERVER_ID.log, where SERVER_ID is the server's
ID.  This file contains an entry for each ordered update that has been
applied to the state machine at the server.  Prime provides a total
order on all updates injected into the system.  Therefore, the files
should be consistent. Note that it is possible that the different
servers have ordered different numbers of updates. However, all
updates ordered by a server should match any corresponding ordered
updates in all other servers.

LATENCY Output: Each client writes the average latency of its update,
measured in seconds, in the file bin/latencies/client_ID.lat, where ID
is the client's ID.  The latency is the time difference from when the
client submitted an update to when it received a message indicating
that the update was ordered.

******************
* Erasure Codes: *
******************
The Prime protocol makes use of erasure codes to send efficient
reconciliation (RECON) messages.  RECON messages keep correct servers
up to date despite the efforts of faulty servers to block execution by
failing to properly disseminate updates.

Prime was developed using Michael Luby's implementation of
Cauchy-based Reed-Solomon erasure codes, which can be downloaded here:

http://www.icsi.berkeley.edu/~luby/

Due to licensing restrictions, we are unable to include this library
in the current release.  By default, the current release performs
reconciliation without using erasure codes (i.e., full PO-Request
messages are sent rather than erasure-encoded ones).  This is less
efficient than using erasure codes but serves the same functional
purpose.  Note that the results from the DSN '08 paper reflect the use
of erasure codes, and thus performance obtained from the current
release in bandwidth-constrained environments will be lower than what
is actually achievable.

The current release is set up to use a generic interface to an erasure
encoding library.  By default, the interface calls are not invoked,
because the USE_ERASURE_CODES flag is set to 0 (see src/def.h).  The
Luby library (or some other erasure encoding library) can be fairly
easily integrated into the current release by setting
USE_ERASURE_CODES to 1 and filling in the implementations of the
interface functions (see src/erasure.h and src/erasure.c).

********************
* Prime Checklist: *
********************
The following is a short summary of the important things that you must do to
run Prime.

1) Download and compile OpenSSL.  Make sure the shared library can be
located, or modify the Makefile to link to the static library
libcrypto.a.

2) Decide on the number of servers in the system, as well as the
number of clients.  Change the parameters in src/def.h
accordingly.  Note that the number of servers must be greater than or
equal to 3*NUM_FAULTS + 1.  (NUM_FAULTS is a parameter in src/def.h).

3) Type make in the src directory.

4) cd to the bin directory. Run the gen_keys program: ./gen_keys

5) Change the bin/address.config file as described above.

6) The server and client programs can now be run.
