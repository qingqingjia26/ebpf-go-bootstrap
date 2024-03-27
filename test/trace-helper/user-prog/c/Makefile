all:open send_pkg
	
open:open.c
	gcc -g -O0 -fno-inline -o open.bin open.c
send_pkg:send_pkg.c 
	gcc -g -O0 -fno-inline -o send_pkg.bin send_pkg.c
clean:
	rm -r *.bin 