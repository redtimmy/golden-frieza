// compile with:
// gcc dlopen_test -o dlopen_test -ldl
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv)
{
        void *handle;
        void (*testalo)();
        char *error;

        handle = dlopen ("./testalo_mod.so", RTLD_LAZY);
        if (!handle) {
            fputs (dlerror(), stderr);
            exit(1);
        }

        testalo = dlsym(handle, "testalo");
        if ((error = dlerror()) != NULL)  {
            fputs(error, stderr);
            exit(1);
        }
        testalo();
        dlclose(handle);
}
