FILE=client
PORT=5025
SERVER=login-faculty.ccs.neu.edu
ID=001740712

run: ${FILE}
	./${FILE} -p ${PORT} ${SERVER} ${ID}

${FILE}: ${FILE}.c
	gcc -g -O0 -o ${FILE} ${FILE}.c

gdb: ${FILE}
	gdb ${FILE}

vi: ${FILE}.c
	vi ${FILE}.c

emacs: ${FILE}.c
	emacs ${FILE}.c

clean:
	rm -f ${FILE} ${FILE}.out