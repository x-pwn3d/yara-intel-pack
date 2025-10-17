// minidump_api_str.c
// simple exe that embeds the string "MiniDumpWriteDump" so YARA can detect it
// compile with:  x86_64-w64-mingw32-gcc -o minidump_test.exe minidump_api_str.c
#include <stdio.h>

int main(void) {
    /* keep the symbol/string in the binary */
    const char *marker = "MiniDumpWriteDump";
    (void)marker;
    return 0;
}
