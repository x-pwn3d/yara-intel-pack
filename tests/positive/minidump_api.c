// minidump_test.c - simple program that references MiniDumpWriteDump
#include <windows.h>
#include <DbgHelp.h>

int main(void) {
    // reference symbol so binary imports DbgHelp.dll
    // we won't actually call it; we just need import
    void *p = (void*) MiniDumpWriteDump;
    return 0;
}
