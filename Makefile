ROOT_DIR=$(shell pwd)
all:
	sudo apt-get install libelf-dev clang llvm libc6-dev-i386
	@ make -C ./src/test_driver
	@ make -C ./src/libbpf-tool/example/c
	@ make -C ./testcases
	@ make -C ./testcases/container
	@ make -C ./testcases/test
	chmod 644 rungui
	chmod 644 systest

clean:
	@ rm -rf $(ROOT_DIR)/*.o

