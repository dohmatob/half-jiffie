all:	page_fault

page_fault: page_fault.o
	gcc page_fault.o -o page_fault

page_fault.o: page_fault.c
	gcc -c page_fault.c

clean:
	rm -rf *.o *~ page_fault