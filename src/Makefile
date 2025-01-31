#
# Prime.
#     
# The contents of this file are subject to the Prime Open-Source
# License, Version 1.0 (the ``License''); you may not use
# this file except in compliance with the License.  You may obtain a
# copy of the License at:
#
# http://www.dsn.jhu.edu/byzrep/prime/LICENSE.txt
#
# or in the file ``LICENSE.txt'' found in this distribution.
#
# Software distributed under the License is distributed on an AS IS basis, 
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
# for the specific language governing rights and limitations under the 
# License.
#
# The Creators of Prime are:
#  Yair Amir, Jonathan Kirsch, and John Lane.
#
# Special thanks to Brian Coan for major contributions to the design of
# the Prime algorithm. 
#  	
# Copyright (c) 2008 - 2010 
# The Johns Hopkins University.
# All rights reserved.
#

INC = -I ../stdutil/src 
STDUTIL_LIB = ../stdutil/lib/libstdutil.a

# Prime can be configured to make use of Spines, an overlay network
# developed at Johns Hopkins (see http://spines.org).  This can be
# useful for testing wide-area topologies and placing bandwidth and
# latency constraints on the links between servers.  By default, the
# system is set up not to use Spines.  In order to use Spines,
# download and compile it, and place it at Prime/spines.  Then
# uncomment the following two lines.
#SPINES = -DSET_USE_SPINES 
#SPINES_LIB = ../spines/spines_lib.a

CC = gcc
CFLAGS = -g -O2 -Wall $(SPINES) $(INC)  

UTIL_OBJ = util/alarm.o util/events.o util/memory.o util/data_link.o

WRAPPER_OBJ = error_wrapper.o openssl_rsa.o

SERVER_OBJ = srv.o data_structs.o utility.o network.o pre_order.o \
	util_dll.o validate.o apply.o dispatcher.o packets.o order.o \
	signature.o tcp_wrapper.o merkle.o \
	erasure.o recon.o $(UTIL_OBJ) $(WRAPPER_OBJ)

CLIENT_OBJ = client.o data_structs.o utility.o pre_order.o util_dll.o \
	packets.o apply.o dispatcher.o order.o \
	signature.o tcp_wrapper.o erasure.o validate.o \
	merkle.o recon.o $(UTIL_OBJ) $(WRAPPER_OBJ)

GEN_KEYS_OBJ = openssl_rsa.o generate_keys.o $(UTIL_OBJ)

all: $(STDUTIL_LIB) server client gen_keys 

$(STDUTIL_LIB):
	cd ../stdutil; make

gen_keys: $(GEN_KEYS_OBJ)
	$(CC) $(CFLAGS) -o ../bin/gen_keys $(GEN_KEYS_OBJ) -lcrypto 

server: $(SERVER_OBJ)
	$(CC) $(CFLAGS) -o ../bin/server $(SERVER_OBJ) $(STDUTIL_LIB) $(SPINES_LIB) -lm -lcrypto 

client: $(CLIENT_OBJ)
	$(CC) -o ../bin/client $(CLIENT_OBJ) $(STDUTIL_LIB) $(SPINES_LIB) -lm -lcrypto 

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $*.o $*.c

clean:
	rm -f *~
	rm -f *.o
	rm -f util/*~
	rm -f util/*.o
	rm -f core*
	rm -f ../bin/server
	rm -f ../bin/client
	rm -f ../bin/gen_keys

# Also cleans up the stdutil library and removes state machine output
# and client latency files
cleaner: clean
	cd ../stdutil; make distclean
	cd ../bin; rm -f state_machine_out.*.log
	cd ../bin/latencies; rm -f client_*.lat

# Also removes all key files
distclean: cleaner
	cd ../bin/keys; rm -f *.pem; rm -f *.key