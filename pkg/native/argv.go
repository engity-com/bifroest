package native

/*
#include <stdlib.h>

char* argv_i(char **argv, int i) {
  return argv[i];
}
*/
import "C"

func ParseCArgv(argc C.int, argv **C.char) []string {
	args := make([]string, int(argc))
	for i := 0; i < int(argc); i++ {
		args[i] = C.GoString(C.argv_i(argv, C.int(i)))
	}
	return args
}
