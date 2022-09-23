#include "header.h"

int main(int argc, char *argv[]) {
    FILE *f1, *f2, *f3, *fptr;
    char pass[20];
	unsigned char *key; /* Key to use for encrpytion and decryption */
	const unsigned char *salt = "SodiumChloride";
	unsigned long iters = 4096;
	char *tempfileName = "temp";
    char *filename;
    char s;
    int socket_file_desc, newsocket_file_desc;

    if((argc==4) && strncmp(*(argv+2),"-d",2)==0) { //for receiving file over network

		int port_number, n, n1;
		socklen_t len_of_client;
		char tbuffer[256];
		struct sockaddr_in server_addr, client_addr;

		fptr = fopen(tempfileName, "wb");
		if (fptr == NULL) {
			printf("ERROR: File open failed \n"); // Error in opening the file.
		}

		socket_file_desc = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_file_desc < 0) {
			printf("ERROR: Socket open failed");
        }
		bzero((char *) &server_addr, sizeof(server_addr));
		port_number = atoi(argv[3]);
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = INADDR_ANY;
		server_addr.sin_port = htons(port_number);
		printf("Waiting for connections..\n");
		if (bind(socket_file_desc, (struct sockaddr *) &server_addr, sizeof(server_addr))< 0) {
			printf("ERROR on binding");
        }
		listen(socket_file_desc, 5);
		len_of_client = sizeof(client_addr);
		newsocket_file_desc = accept(socket_file_desc, (struct sockaddr *) &client_addr, &len_of_client);
		printf("Inbound file..\n");
		if (newsocket_file_desc < 0) {
			printf("ERROR: Accept failed");
        }
		while (1) {
			bzero(tbuffer, 256);
			n = read(newsocket_file_desc, tbuffer, 255);
			if (n < 0)
				printf("ERROR reading from socket");
			if (n == 0)
				break;
			n1 = fwrite(tbuffer, sizeof(char), n, fptr);
		}
		fclose(fptr);

        // struct for storing cipher information like key, iv , type
        cipher_params_t *cipher_params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
        if (!cipher_params) {
            fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno)); //memory allocation failed
            return errno;
        }

        // Prompt user for password
        printf("%s", "Password: ");
        scanf("%s", pass);
        printf("\n");

        // Key allocation
        key = (unsigned char *) malloc(16);
        PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, 14, iters, EVP_sha3_256(), 16, key);

        printf("Key: \n");
        BIO_dump_fp(stdout, (unsigned char *)key, 16);
        printf("\n");

        iv = (unsigned char *) malloc(16);
        
        cipher_params->key = key;
        cipher_params->iv = iv;
        cipher_params->encrypt = 0;
        cipher_params->cipher_type = EVP_aes_256_gcm();
        
        fptr = fopen("encrypt_file", "rb");
        printf("File contents received after encryption: \n");
        BIO_dump_fp(stdout, fptr, findFileSize(fptr));
        printf("\n");

        if (!fptr) {
            fprintf(stderr, "ERROR: file open error: %s\n", strerror(errno)); // File open failed
            return errno;
        }


        if (!isFilePresent("encrypt_file")) {
            f3 = fopen(argv[1], "wb");
            if (!f3) {
                fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno)); // File open failed
                return errno;
            }

            // calling decrypt function
            decrypt_file(cipher_params, fptr, f3);

            fclose(f3);

            printf("Decrypted Text: \n");
            f3 = fopen(argv[1], "rb");
            char s;
            char *ptr = NULL;
            char ar[400];
            while( (ptr = fgets(ar,sizeof(ar), f3)) != NULL) {  
                printf("%s",ptr);
                /* fgets() copies \n t the end of tbuffer, if you don't want remove it by some logic */ 
            }
            printf("\n");

            
            fclose(fptr); // File descrriptors closed
            fclose(f3);

            
            free(cipher_params); // Free memory stored by structs

            return 0;
        }
        else {
            printf("This file has already been received! \n");
            return 33;
        }
    }

    else if((argc==3) && strncmp(*(argv+2),"-l",2)==0) { //for 'local' operation

        unsigned char *IV = (unsigned char *) malloc(16); // IV pointer
        char writeFile[strlen(*(argv+1))-6]; // removing .ufsec by subtracting -6 from length
        strncpy(writeFile,*(argv+1),strlen(*(argv+1))-6);
        writeFile[strlen(*(argv+1))-6] = '\0';
        // Allocate memory to cipher_params struct
        cipher_params_t *cipher_params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
        iv = (unsigned char *) malloc(16);
        if (!cipher_params) {
            fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
            return errno;
        }
        
        // Prompt user to enter password 
        printf("%s", "Password: ");
        scanf("%s", pass);

        // Allocate memory to key
        key = (unsigned char *) malloc(16);

        // Generating encryption key using PBKF2
        PKCS5_PBKDF2_HMAC(pass, 4, salt, 14, iters, EVP_sha3_256(), 16, key);

        // Printing key
        printf("Key is:\n");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", (unsigned char) key[i]);
        }
        printf("\n");

        // Generating random IV
        RAND_bytes(IV, sizeof(IV));
        
        cipher_params->key = key;
        cipher_params->iv = iv;
        cipher_params->encrypt = 0;
        cipher_params->cipher_type = EVP_aes_256_gcm();

        // Opening the file provided for reading
        f1 = fopen(argv[1], "rb");
        if (!f1) {
            fprintf(stderr, "ERR: file open error: %s\n", strerror(errno));
            return errno;
        }
        
        printf("Content of file recieved after ecnryption: \n");
        BIO_dump_fp(stdout, f1, findFileSize(f1));
        printf("\n");

        // Opening the decypted file for writing
        f3 = fopen(writeFile, "wb");
        if (!f3) {
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }

        // Calling decrypt function with file pointers to decrypt input file
        decrypt_file(cipher_params, f1, f3);

        // Close the open file descriptors
        
        fclose(f3);
        f3 = fopen(writeFile, "r");
        char s;
        printf("Decrypted text:\n");
        char *ptr = NULL;
        char ar[400];
        while( (ptr = fgets(ar,sizeof(ar), f3)) != NULL) {  
            printf("%s",ptr);
            /* fgets() copies \n t the end of tbuffer, if you don't want remove it by some logic */ 
        }
        printf("\n");
        

        // Memory allocation freed
        fclose(f1);
        fclose(f3);
        free(cipher_params);

        return 0;
        
    }
    else {
        printf("Invalid option(s) given!\n");
        return 1;
    }
}
