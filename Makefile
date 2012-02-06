tsinfo: tsinfo.o convtounicode.o
	gcc -g -o tsinfo tsinfo.o convtounicode.o

tsinfo.o: tsinfo.c
	gcc -g -c tsinfo.c
convtounicode.o: convtounicode.c
	gcc -g -c convtounicode.c

clean:
	rm -f *.o
