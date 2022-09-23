#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/bio.h>

#define BUFFER_SIZE 1024

// /* Initialization Vector */
unsigned char *iv;

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

//Returns 1 if the file exists, 0 otherwise.
int isFilePresent (const char *filename)
{
  FILE *f=NULL;
  if(f == fopen(filename,"r"))
  {
    fclose(f);
    return 1;
  }
  return 0;
}

//Returns the size of file (in bytes).
int findFileSize(FILE* f)
{
    fseek(f, 0, SEEK_END);
    int len = ftell(f);
    rewind(f);
    return len;
}

void encrypt_file(cipher_params_t *cipher_params, FILE *f1, FILE *f2) {
    int size_of_block = EVP_CIPHER_block_size(cipher_params->cipher_type);
    unsigned char input_buffer[BUFFER_SIZE];

    // Allocating extra memory to output buffer to hold additional block
    unsigned char output_buffer[BUFFER_SIZE + size_of_block];

    int number_of_bytes;
    int output_length;

    // Allocates and returns a cipher context.
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Error handling if allocation error
    if(ctx == NULL){
        fprintf(stderr, "ERROR: Error in EVP_CIPHER_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-1);
    }

    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, cipher_params->cipher_type, NULL, NULL, NULL, cipher_params->encrypt)){
        fprintf(stderr, "ERROR: Error in EVP_CipherInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-1);
    }

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, cipher_params->key, cipher_params->iv, cipher_params->encrypt)){
        fprintf(stderr, "ERROR: Error in EVP_CipherInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-1);
    }

    while(1){
        // Read in data in blocks until EOF.
        number_of_bytes = fread(input_buffer, sizeof(unsigned char), BUFFER_SIZE, f1);
        if (ferror(f1)){
            fprintf(stderr, "ERROR: file read error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(errno);           
        }

        // Updating the cipher on every read.
        if(!EVP_CipherUpdate(ctx, output_buffer, &output_length, input_buffer, number_of_bytes)){
            fprintf(stderr, "ERROR: Error in EVP_CipherUpdate: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(-3);
        }

        // Writing encrypted text to output file
        fwrite(output_buffer, sizeof(unsigned char), output_length, f2);
        if (ferror(f2)) {
            fprintf(stderr, "ERROR: file write error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(errno);
        }
        // Checking for EOF
        if (number_of_bytes < BUFFER_SIZE) {
            break;
        }
    }

    // Ciphering final block
    EVP_CipherFinal_ex(ctx, output_buffer, &output_length);
    
    // Write the final block to output file
    fwrite(output_buffer, sizeof(unsigned char), output_length, f2);
    if (ferror(f2)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

// Function to decrypt file contents in f1 and copy to f2
void decrypt_file(cipher_params_t *cipher_params, FILE *f1, FILE *f2) {
    // size of block in EVP_aes_256_gcm algorithm
    int size_of_block = EVP_CIPHER_block_size(cipher_params->cipher_type);

    // creating input buffer for reading
    unsigned char input_buffer[BUFFER_SIZE];

    // Allocating extra memory to output buffer to hold addition block
    unsigned char output_buffer[BUFFER_SIZE + size_of_block];

    int number_of_bytes;
    int output_length;

    // Allocates and returns a cipher context.
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Error handling for cipher context allocating error
    if(ctx == NULL){
        fprintf(stderr, "ERROR: Error in EVP_CIPHER_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-3);
    }

    if(!EVP_CipherInit_ex(ctx, cipher_params->cipher_type, NULL, NULL, NULL, cipher_params->encrypt)){
        fprintf(stderr, "ERROR: Error in EVP_CipherInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-1);
    }

    // Setting key and IV
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, cipher_params->key, cipher_params->iv, cipher_params->encrypt)){
        fprintf(stderr, "ERROR: Error in EVP_CipherInit_ex: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-1);
    }

    while(1){
        // Reading data blocks until end of file.
        number_of_bytes = fread(input_buffer, sizeof(unsigned char), BUFFER_SIZE, f1);
        if (ferror(f1)){
            fprintf(stderr, "ERROR: file read error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(errno);
        }

        //  Updating the cipher on every read.
        if(!EVP_CipherUpdate(ctx, output_buffer, &output_length, input_buffer, number_of_bytes)){
            fprintf(stderr, "ERROR: Error EVP_CipherUpdate: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(-2);
        }

        // Writing the decrypted text in output file
        fwrite(output_buffer, sizeof(unsigned char), output_length, f2);
        if (ferror(f2)) {
            fprintf(stderr, "ERROR: file write error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            free(cipher_params);
            fclose(f1);
            fclose(f2);
            exit(errno);
        }

        // Checking EOF
        if (number_of_bytes < BUFFER_SIZE) {
            break;
        }
    }

    // Decrypting final block
    EVP_CipherFinal_ex(ctx, output_buffer, &output_length);
    
    // Writing final block to output file.
    fwrite(output_buffer, sizeof(unsigned char), output_length, f2);
    if (ferror(f2)) {
        fprintf(stderr, "ERROR: file write error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        free(cipher_params);
        fclose(f1);
        fclose(f2);
        exit(-3);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}