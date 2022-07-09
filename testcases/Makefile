SRC_LIBLTT :=$(abspath ../src/lib/test.c)
OBJ_LIBLTT :=$(patsubst %.c, %.o, $(SRC_LIBLTT))
LIB_OBJ :=$(abspath ../src/lib/libtest.a)
INCLUDES :=-I ../include
CFLAGS := -g -Wall

all:$(LIB_OBJ) 


$(LIB_OBJ):$(OBJ_LIBLTT)
	ar -crv $(LIB_OBJ) $(OBJ_LIBLTT)

$(OBJ_LIBLTT):$(SRC_LIBLTT)
	gcc -c $< -o $(OBJ_LIBLTT) $(INCLUDES)


