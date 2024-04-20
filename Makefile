SRCS = \
	bech32.cxx \
	main.cxx

OBJS = $(subst .cc,.o,$(subst .cxx,.o,$(subst .cpp,.o,$(SRCS))))

CXXFLAGS = -std=c++17 -static
LIBS = -static-libgcc -static-libstdc++ -lcpprest -lcrypto -lsecp256k1
TARGET = nostr-bot
ifeq ($(OS),Windows_NT)
TARGET := $(TARGET).exe
endif

.SUFFIXES: .cpp .cc .cxx .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	g++ -o $@ $(OBJS) $(LIBS)

.cxx.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cpp.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cc.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

clean :
	rm -f *.o $(TARGET)