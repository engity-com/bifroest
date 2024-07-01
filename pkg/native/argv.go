package native

/*
#include <stdlib.h>

char* argv_i(char **argv, int i) {
  return argv[i];
}
*/
import "C"
import "unsafe"

func ParseCArgv(argc int, argv unsafe.Pointer) []string {
	args := make([]string, argc)
	for i := 0; i < argc; i++ {
		args[i] = C.GoString(C.argv_i((**C.char)(argv), C.int(i)))
	}
	return args
}
