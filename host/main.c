/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _CRT_SECURE_NO_WARNINGS
#define _MAX_LEN 20

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = { 0 };
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	FILE* fp = NULL;
	FILE* fp2 = NULL;
	char buffer[_MAX_LEN];
	char key;
	char ciphertext[_MAX_LEN] = {0,};
	int len=_MAX_LEN;

	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	
	if (strcmp(argv[1], "-e") == 0)
	{
		printf("encrypted\n");
		/* Read plaintext file */
		printf("========================Read file========================\n");
		printf("Text file name : %s\n", argv[2]);
		
		fp = fopen(argv[2], "r");
		if (fp == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		
		fread(buffer, sizeof(buffer), 1, fp);
		printf("plaintext : %s\n", buffer);
		fclose(fp);

		/*
		 * Prepare the argument. Pass a value in the first parameter,
		 * the remaining three parameters are unused.
		 */
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		/*
		 * TA_EXAMPLE_RANDOM_GENERATE is the actual function in the TA to be
		 * called.
		 */
		printf("===================Generate Random Key==================\n");
		printf("Invoking TA to generate random UUID... \n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_GENERATE_KEY,
					 &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		
		/* Encryption plaintext */
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = buffer;
		op.params[0].tmpref.size = len;
		
		printf("================Encryption File========================\n");
		memcpy(op.params[0].tmpref.buffer, buffer, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_ENC_MESSAGE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Success Message Encryption %s\n", argv[2]);
		
		printf("========================File Save========================\n");
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("ciphertext : %s\n", ciphertext);

		fp = fopen("encryptedFile.txt", "wb");
		if (fp == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		fwrite(ciphertext, strlen(ciphertext), 1, fp);
		fclose(fp);
		printf("Success File Save!! File name is %s\n", "encryptedFile.txt");
		
		printf("================Encryption Key=========================\n");
		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].value.a = 0;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_ENC_KEY, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Success key Encryption\n");

		printf("========================File Save========================\n");
		printf("ecnryted key : %c\n", op.params[0].value.a);
		fp = fopen("encryptedKey.txt", "wb");
		if (fp == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		int tmp = op.params[0].value.a;
		fprintf(fp, "%c", tmp);
		fclose(fp);
	}
	else if (strcmp(argv[1], "-d") == 0)
	{
		printf("decrypted\n");
		/* Read plaintext file */
		printf("========================Read file========================\n");
		printf("Text file name : %s\n", argv[2]);
		
		fp = fopen(argv[2], "r");
		fp2 = fopen(argv[3], "r");
		if (fp == NULL)
		{
			fprintf(stderr, "Decryption File Open Error!\n");
			exit(1);
		}
		if (fp2 == NULL)
		{
			fprintf(stderr, "Decryption Key Open Error!\n");
			exit(1);
		}
		fread(buffer, sizeof(buffer), 1, fp);
		key = fgetc(fp2);
		printf("ciphertext : %s\n", buffer);
		printf("cipherkey : %c\n", key);
		fclose(fp);
		fclose(fp2);
		
		/* Decryption Key */
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		
		
		printf("================Dencryption Key========================\n");
		op.params[0].value.a = key;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_DEC_KEY, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Success key Dencryption\n");

		/* Dencryption ciphertext */
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = buffer;
		op.params[0].tmpref.size = len;
		
		printf("================decrypted File========================\n");
		memcpy(op.params[0].tmpref.buffer, buffer, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_DEC_MESSAGE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Success Message decrypted %s\n", argv[2]);

		printf("========================File Save========================\n");
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("plaintext : %s\n", ciphertext);
		fp = fopen("decryptedKey.txt", "wb");
		if (fp == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		fwrite(ciphertext, strlen(ciphertext), 1, fp);
		fclose(fp);
		printf("Success File Save!! File name is %s\n", "decryptedKey.txt");
	}
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
	return 0;
}
