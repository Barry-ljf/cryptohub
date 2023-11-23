# The location of pcsi-sum's deps, change 
# it according to your own build config.
PCSI_SUM_DEP = /home/ljf/pcsi_test/pcsi_deps

PCSI_SUM_BASE = $(wildcard src/common/*.cpp)
PCSI_SUM_BASE += $(wildcard src/ot/*.cpp)
PCSI_SUM_BASE += $(wildcard src/poly/*.cpp)

PCSI_SUM_CLIENT = test/pcsi_client.cpp
PCSI_SUM_SERVER = test/pcsi_server.cpp
PCSI_SUM_TEST = test/pcsi_sum_test.cpp

CFLAGS = -I ${PCSI_SUM_DEP}/include/ -I ${PCSI_SUM_DEP}/include/HashingTables/ -I src/
CFLAGS += -no-pie -pthread -maes -msse2 -msse3 -msse4.1 -mpclmul -mavx -mavx2 -mbmi2
CFLAGS += -std=c++17

DEP_LIBS= -laby -l HashingTables -llibOTe -lSimplestOT -lcryptoTools
DEP_LIBS += -lrelic -lgmp -lssl -lcrypto -lotextension -lencrypto_utils

LDFLAGS = -L ${PCSI_SUM_DEP}/lib/ ${LINK_LIBRARY}
LDFLAGS += -L ${PCSI_SUM_DEP}/lib/x86_64-linux-gnu/
LDFLAGS += ${DEP_LIBS}

all: pcsi_server pcsi_client pcsi_test 

pcsi_server: ${PCSI_SUM_BASE} ${PCSI_SUM_SERVER}
	g++ $^ -o $@ ${CFLAGS} ${LDFLAGS}

pcsi_client: ${PCSI_SUM_BASE} ${PCSI_SUM_CLIENT}
	g++ $^ -o $@ ${CFLAGS} ${LDFLAGS}

pcsi_test: ${PCSI_SUM_BASE} ${PCSI_SUM_TEST}
	g++ $^ -o $@ ${CFLAGS} ${LDFLAGS}

.PHONY: clean
clean:
	@rm -rf ./pcsi_server ./pcsi_client ./pcsi_test
