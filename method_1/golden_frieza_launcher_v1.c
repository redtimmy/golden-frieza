/*
 * golden_frieza_launcher_v1.c
 * Coded by: Marco Ortisi - RedTimmy Security
 *
 * Compile with:
 * gcc golden_freiza_launcher_v1.c -o golden_freiza_launcher_v1 -ldl
 *
 * */
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>

// RC4 function ripped from: https://github.com/kmohamed2020/rc4
void RC4(unsigned char* data, long dataLen, unsigned char* key, long keyLen,unsigned char* result)
/*
 * Function to encrypt data represented in array of char "data" with length represented in dataLen
 * using key which is represented in "Key" with length represented in "keyLen", and result will be
 * stored in result
 *
*/
{
    unsigned char T[256];
    unsigned char S[256];
    unsigned char  tmp; // to be used in swaping
    int j = 0,t= 0,i= 0;


    /* S & K initialization */
    for(int i = 0 ; i < 256 ; i++)
    {
        S[i]=i;
        T[i]= key[i % keyLen];
    }
    /* State Permutation */
    for(int i = 0 ; i < 256; i++)
    {
        j = ( j + S[i] + T[i] ) % 256;

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;
    }
    j =0; // reintializing j to reuse it
    for(int x = 0 ; x< dataLen ; x++)
    {
        i = (i+1) % 256; // using %256 to avoid exceed the array limit
        j = (j + S[i])% 256; // using %256 to avoid exceed the array limit

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;

        t = (S[i] + S[j]) % 256;

        // XOR generated S[t] with Byte from the plaintext/cipher and append each
        // Encrypted/Decrypted byte to result array
        result[x]= data[x]^S[t];
    }
}

int main(int argc, char **argv)
{
        /* paramater acquisition */
        char *key;
        int offset = 0, len = 0;
        struct termios oflags, nflags;

        /* encrypted module loading */
        void *handle;

        /* pid and /proc/pid/maps reading */
        char line[256];
        char proc_path[32];
        int ret;
        unsigned long start_address = 0, end_address = 0;
        pid_t ppid;
        char *module_name;
        FILE *f;

        /* extract memory into a buffer in order to decrypt it */
        char *enc_buffer;
        int n;

        /* transfer control to final destination */
        void (*testalo)();

        /* other */
        char *error;

        if (!argv[1])
        {
                fprintf(stderr, "A parameter is needed from command line\n");
                exit(-1);
        }

        /***************************************************************
         *  PARAMETERS ACQUISITION
         **************************************************************/
        /* Offset and Len in the binary */
        printf("Enter offset and len in hex (0xXX): ");
        scanf("%x %x", &offset, &len);
        printf("Offset is %d bytes\n", offset);
        printf("Len is %d bytes\n", len);
        getchar();

        /* key */
        key = calloc(256, sizeof(char));
        if (!key)
        {
                fprintf(stderr, "memory error\n");
                exit(-1);
        }

        /* disabling echo */
        tcgetattr(fileno(stdin), &oflags);
        nflags = oflags;
        nflags.c_lflag &= ~ECHO;
        nflags.c_lflag |= ECHONL;

        if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0)
        {
                fprintf(stderr, "tcsetattr\n");
                exit(-1);
        }

        printf("Enter key: ");
        scanf("%16s", key);
        //printf("Key is: %s\n", key);

        /* restore terminal */
        if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0)
        {
                fprintf(stderr, "tcsetattr\n");
                exit(-1);
        }

        /******************************************************************
         * ENCRYPTED MODULE LOADING
         *****************************************************************/
        /* Load the encrypted module in memory */
        handle = dlopen (argv[1], RTLD_LAZY);
        if (!handle) {
            fputs(dlerror(), stderr);
            fputs("\n", stderr);
            exit(1);
        }

        /*****************************************************************
         * PID AND /PROC/PID/MAPS READING
         ****************************************************************/

        ppid = getpid();
        printf("PID is: %d\n", ppid);
        snprintf(proc_path, sizeof(proc_path)-1, "/proc/%d/maps", ppid);

        f = fopen(proc_path, "r");
        if (!f)
        {
                fprintf(stderr, "Unable to open memory mapping file\n");
                exit(-1);
        }

        module_name = basename(argv[1]);
        printf("Module name is: %s\n", module_name);

        while (fgets(line, 256, f) != NULL)
        {
                if (strstr(line, module_name))
                {
                        printf("%s", line);
                        sscanf(line, "%p-%p", (void **)&start_address, (void **)&end_address);
                        break;
                }
        }
        fclose(f);

        if (start_address == 0 || end_address == 0)
        {
                fprintf(stderr, "Module %s not mapped\n", module_name);
                exit(-1);
        }
        printf("Start address is: %p\n", (void *)start_address);
        printf("End address is %p\n", (void *)end_address);

        /**********************************************************************
         * EXTRACT MEMORY INTO A BUFFER IN ORDER TO DECRYPT IT
         *********************************************************************/

        /* copy encrypted text from module to memory */
        enc_buffer = (char *)malloc(len+1);
        if (!enc_buffer)
        {
                fprintf(stderr, "malloc error\n");
                exit(-1);
        }
        memset(enc_buffer, '\0', len+1);
        memcpy(enc_buffer, (void *)start_address+offset, len);

        /* mark start_address up to end_address as writable */
        n = end_address - start_address;

        if (mprotect((void *)start_address, n, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        {
                fprintf(stderr, "mprotect() error\n");
                exit(-1);
        }

        /* decryption */
        RC4(enc_buffer, len, key, strlen(key), (void *)start_address+offset);
        memset(key, '\0', strlen(key));
        free(enc_buffer);

        /* mark memory not writable again */
        if (mprotect((void *)start_address, n, PROT_READ | PROT_EXEC) == -1)
        {
                fprintf(stderr, "mprotect() error\n");
                exit(-1);
        }

        /***************************************************************************************
         * TRANSFER CONTROL TO FINAL DESTINATION
         **************************************************************************************/

        /* paramater part to be implemented */
        testalo = dlsym(handle, "testalo");
        if ((error = dlerror()) != NULL)  {
            fputs(error, stderr);
            exit(1);
        }
        printf("\nExecution of .text\n==================\n");
        testalo();
        dlclose(handle);
}
