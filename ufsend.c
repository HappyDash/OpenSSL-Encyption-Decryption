#include "header.h"

int main(int argc, char *argv[])
{

    char pass[20];                                // password for key generation
    unsigned char *key;                           // Cipher key
    const unsigned char *salt = "SodiumChloride"; // Salt hardcoded as 'SodiumChloride'
    unsigned long iters = 4096;                   // total iterations
    FILE *f1, *f2, *f3, *f4;                      // file pointers

    // sending file over network
    if ((argc == 4) && strncmp(*(argv + 2), "-d", 2) == 0)
    {

        int socket_file_desc;
        int port_num;
        int n;
        char *ip_address;
        char *port_number;
        char *fileContents;
        int fileSize;
        struct sockaddr_in add_of_server;
        struct hostent *server;
        struct in_addr ipv4_addr;

        cipher_params_t *cipher_params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
        if (!cipher_params)
        {
            fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno)); // Memory allocation error
            return errno;
        }
        // Prompt user to provide password
        printf("%s", "Password: ");
        scanf("%s", pass);
        printf("\n");

        key = (unsigned char *)malloc(16);
        PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, 14, iters, EVP_sha3_256(), 16, key);

        printf("Key: \n");
        BIO_dump_fp(stdout, (unsigned char *)key, 16);
        printf("\n");

        cipher_params->key = key;
        cipher_params->iv = iv;
        cipher_params->encrypt = 1; // 1 for encryption, 0 for decryption
        cipher_params->cipher_type = EVP_aes_256_gcm();

        f1 = fopen(argv[1], "rb");
        if (!f1)
        {
            fprintf(stderr, "ERR: file open error: %s\n", strerror(errno));
            return errno;
        }

        char s;
        printf("Plaintext:\n");
        char *ptr = NULL;
        char ar[10000];
        while ((ptr = fgets(ar, sizeof(ar), f1)) != NULL)
        {
            printf("%s", ptr);
            /* fgets() copies \n t the end of buffer, if you don't want remove it  by some logic */
        }
        printf("\n");
        fclose(f1);

        // Opening given file for reading
        f1 = fopen(argv[1], "rb");
        if (!f1)
        {
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno)); // Opening file for read failed
            return errno;
        }

        f4 = fopen("encrypt_file", "wb");

        encrypt_file(cipher_params, f1, f4); // Calling encryption function to encrypt given file

        fileSize = findFileSize(f4);
        fileContents = (char *)malloc(fileSize * sizeof(char)); // an array buffer to read file contents

        printf("Sending encrypted text to server: \n");
        BIO_dump_fp(stdout, f4, fileSize);
        printf("\n");
        fclose(f4);

        //separate the ip_address and port_number
        ip_address = strtok(argv[3], ":");
        port_number = strtok(NULL, ":");

        port_num = atoi(port_number);
        socket_file_desc = socket(AF_INET, SOCK_STREAM, 0); //Create and open a socket
        if (socket_file_desc < 0)
            printf("ERROR: Socket Opening failed \n");
        inet_pton(AF_INET, ip_address, &ipv4_addr);
        server = gethostbyaddr(&ipv4_addr, sizeof &ipv4_addr, AF_INET); //getting server details from IP address
        if (server == NULL)
        {
            printf("Host doesn't exists\n");
        }
        bzero((char *)&add_of_server, sizeof(add_of_server));

        add_of_server.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&add_of_server.sin_addr.s_addr, server->h_length);
        add_of_server.sin_port = htons(port_num);
        if (connect(socket_file_desc, (struct sockaddr *)&add_of_server, sizeof(add_of_server)) < 0)
        { // connecting to server
            printf("ERROR connecting");
        }

        // Send ciphertext to server
        n = write(socket_file_desc, fileContents, fileSize);
        if (n < 0)
            printf("ERROR: Write to socket failed");
        close(socket_file_desc);
        printf("Successfully encrypted and sent to server at %s (%i bytes transmitted)\n", ip_address, fileSize);
        fclose(f1);
    }

    else if ((argc == 3) && strncmp(*(argv + 2), "-l", 2) == 0)
    { //for 'local' operation

        unsigned char *IV = (unsigned char *)malloc(16);
        char writeFile[strlen(*(argv + 1)) + 6];
        memset(writeFile, 0, strlen(*(argv + 1)) + 6);
        strcpy(writeFile, *(argv + 1));
        strcat(writeFile, ".ufsec");
        // Allocate memory to params struct
        cipher_params_t *cipher_params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
        iv = (unsigned char *)malloc(16);
        if (!cipher_params)
        {
            fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
            return errno;
        }

        // Prompt user to enter password
        printf("%s", "Password: ");
        scanf("%s", pass);

        // Allocate memory to key
        key = (unsigned char *)malloc(16);

        // Generating encryption key using PBKF2
        PKCS5_PBKDF2_HMAC(pass, 4, salt, 14, iters, EVP_sha3_256(), 16, key);

        // Printing key
        printf("Key:\n");
        BIO_dump_fp(stdout, (unsigned char *)key, 16);
        printf("\n");

        // Generating random IV
        RAND_bytes(IV, sizeof(IV));

        cipher_params->key = key;
        cipher_params->iv = iv;
        cipher_params->encrypt = 1;
        cipher_params->cipher_type = EVP_aes_256_gcm();

        // Opening the file provided for reading
        f1 = fopen(argv[1], "rb");
        if (!f1)
        {
            fprintf(stderr, "ERR: file open error: %s\n", strerror(errno));
            return errno;
        }

        char s;
        printf("Plaintext:\n");
        char *ptr = NULL;
        char ar[1000];
        while ((ptr = fgets(ar, sizeof(ar), f1)) != NULL)
        {
            printf("%s", ptr);
            /* fgets() copies \n t the end of buffer, if you don't want remove it  by some logic */
        }
        printf("\n");
        fclose(f1);
        f1 = fopen(argv[1], "rb");
        if (!f1)
        {
            fprintf(stderr, "ERR: file open error: %s\n", strerror(errno));
            return errno;
        }
        // Opening the decypted file for writing
        f2 = fopen(writeFile, "wb");
        if (!f2)
        {
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }

        // Calling decrypt function with file pointers to decrypt input file
        encrypt_file(cipher_params, f1, f2);
        int encFileSize = findFileSize(f2);

        printf("Encrypted text: \n");
        BIO_dump_fp(stdout, f2, encFileSize);
        printf("\n");

        // Close the open file descriptors
        fclose(f1);
        fclose(f2);

        // Memory allocation freed
        free(cipher_params);

        return 0;
    }

    else
    {
        printf("Invalid option(s) given!\n");
        return 1;
    }
}
