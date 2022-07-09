SRC :=$(wildcard *.c)
OBJS :=$(patsubst %.c, %, $(SRC))
LIB :=-L $(abspath ../../src/lib) -ltest
INCLUDES :=-I ../../include
CFLAGS := -g -Wall
OBJ_DIR := ../bin

all:$(OBJS)



%:%.c
	gcc -g $< -o $(OBJ_DIR)/$@ $(INCLUDES)  $(LIB) 

