NAME := ldap
LIBS := -l secur32 -l netapi32 -l wldap32 -l advapi32 -l rpcrt4
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all: obj bin

obj:
	mkdir -p ./o
	$(CC_x64) -o ./o/$(NAME).x64.o -Os -c ldap.c -DBOF
	$(CC_x86) -o ./o/$(NAME).x86.o -Os -c ldap.c -DBOF

bin:
	mkdir -p ./exe
	$(CC_x64) ldap.c $(LIBS) -o ./exe/$(NAME).x64.exe
	$(CC_x86) ldap.c $(LIBS) -o ./exe/$(NAME).x86.exe

clean:
	rm -rf ./o/$(NAME).*.o
	rm -rf ./exe/$(NAME).*.exe
