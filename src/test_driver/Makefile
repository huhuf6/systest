SRC :=$(wildcard *.c)
OBJS :=$(patsubst %.c, %.o, $(SRC))
INCLUDES :=-I ../../include
OUTPUT_DIR :=../../bin

MAKE_TARGETS := test-driver


all:$(MAKE_TARGETS)

test-driver:test-driver.o zoolib.o splitstr.o cJSON.o
	gcc -o   $(OUTPUT_DIR)/$@ $^
	
%.o:%.c
	gcc -g -c $< -o $@ $(INCLUDES) 
	
clean:
	rm ./*.o 
