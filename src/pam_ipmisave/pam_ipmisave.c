/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/*
 * This module is intended to save password of  special group user
 *
 */

#define MAX_SPEC_GRP_PASS_LENGTH 20
#define MAX_SPEC_GRP_USER_LENGTH 16
#define MAX_KEY_SIZE 8
#define DEFAULT_SPEC_PASS_FILE "/etc/ipmi-pass"
#define META_PASSWD_SIG "=OPENBMC="
#define block_round(ODD, BLK)                                                  \
	((ODD) + (((BLK) - ((ODD) & ((BLK)-1))) & ((BLK)-1)))

/*
 * Meta data struct for storing the encrypted password file
 */
typedef struct metapassstruct {
	char signature[10];
	unsigned char reseved[2];
	size_t hashsize;
	size_t ivsize;
	size_t datasize;
	size_t padsize;
	size_t macsize;
} metapassstruct;

int lock_pwdf(void)
{
	int i;
	int retval;

	i = 0;
	while ((retval = lckpwdf()) != 0 && i < 100) {
		usleep(1000);
		i++;
	}
	if (retval != 0) {
		return PAM_AUTHTOK_LOCK_BUSY;
	}
	return PAM_SUCCESS;
}

void unlock_pwdf(void)
{
	ulckpwdf();
}

static const char *get_option(const pam_handle_t *pamh, const char *option,
			      int argc, const char **argv)
{
	int i;
	size_t len;

	len = strlen(option);

	for (i = 0; i < argc; ++i) {
		if (strncmp(option, argv[i], len) == 0) {
			if (argv[i][len] == '=') {
				return &argv[i][len + 1];
			}
		}
	}
	return NULL;
}

int encrypt_decrypt_data(const pam_handle_t *pamh, int isencrypt,
			 const EVP_CIPHER *cipher, const char *key,
			 size_t keylen, const char *iv, size_t ivlen,
			 const char *inbytes, size_t inbyteslen, char *outbytes,
			 size_t *outbyteslen, char *mac, size_t *maclen)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_MD *digest = EVP_sha256();
	size_t outEVPlen = 0;
	int retval = 0;
	size_t outlen = 0;

	if (cipher == NULL || key == NULL || iv == NULL || inbytes == NULL
	    || outbytes == NULL || mac == NULL || inbyteslen == 0
	    || EVP_CIPHER_key_length(cipher) > keylen
	    || EVP_CIPHER_iv_length(cipher) > ivlen) {
		pam_syslog(pamh, LOG_DEBUG, "Invalid inputs");
		return -1;
	}

	if (!isencrypt) {
		char calmac[EVP_MAX_MD_SIZE];
		size_t calmaclen = 0;
		// calculate MAC for the encrypted message.
		if (NULL
		    == HMAC(digest, key, keylen, inbytes, inbyteslen, calmac,
			    &calmaclen)) {
			pam_syslog(pamh, LOG_DEBUG,
				   "Failed to verify authentication %d",
				   retval);
			return -1;
		}
		if (!((calmaclen == *maclen)
		      && (memcmp(calmac, mac, calmaclen) == 0))) {
			pam_syslog(pamh, LOG_DEBUG,
				   "Authenticated message doesn't match %d, %d",
				   calmaclen, *maclen);
			return -1;
		}
	}

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_padding(ctx, 1);

	// Set key & IV
	retval = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, isencrypt);
	if (!retval) {
		pam_syslog(pamh, LOG_DEBUG, "EVP_CipherInit_ex failed with %d",
			   retval);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if ((retval = EVP_CipherUpdate(ctx, outbytes + outlen, &outEVPlen,
				       inbytes, inbyteslen))) {
		outlen += outEVPlen;
		if ((retval = EVP_CipherFinal(ctx, outbytes + outlen,
					      &outEVPlen))) {
			outlen += outEVPlen;
			*outbyteslen = outlen;
		} else {
			pam_syslog(pamh, LOG_DEBUG,
				   "EVP_CipherFinal returns with %d", retval);
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}
	} else {
		pam_syslog(pamh, LOG_DEBUG, "EVP_CipherUpdate returns with %d",
			   retval);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	EVP_CIPHER_CTX_free(ctx);

	if (isencrypt) {
		// Create MAC for the encrypted message.
		if (NULL
		    == HMAC(digest, key, keylen, outbytes, *outbyteslen, mac,
			    maclen)) {
			pam_syslog(pamh, LOG_DEBUG,
				   "Failed to create authentication %d",
				   retval);
			return -1;
		}
	}
	return 0;
}


int update_pass_special_file(const pam_handle_t *pamh, const char *keyfilename,
			     const char *filename, const char *forwho,
			     const char *towhat)
{
	struct stat st;
	FILE *pwfile, *opwfile, *keyfile;
	int err = 0, wroteentry = 0, oldmask, fd;
	char tempfilename[1024];
	size_t forwholen = strlen(forwho);
	size_t towhatlen = strlen(towhat);
	char keybuff[MAX_KEY_SIZE] = {0};
	size_t keybuffsize = sizeof(keybuff);

	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	const EVP_MD *digest = EVP_sha256();

	char *linebuff = NULL, *opwfilebuff = NULL, *opwptext = NULL;
	size_t opwptextlen = 0, opwfilesize = 0;
	metapassstruct *opwmp = NULL;

	char *pwptext = NULL, *pwctext = NULL;
	size_t pwctextlen = 0, pwptextlen = 0, maclen = 0;
	size_t writtensize = 0, keylen = 0;
	metapassstruct pwmp = {META_PASSWD_SIG, {0, 0}, .0, 0, 0, 0, 0};
	char mac[EVP_MAX_MD_SIZE] = {0};
	unsigned char key[EVP_MAX_KEY_LENGTH];
	char iv[EVP_CIPHER_iv_length(cipher)];
	char hash[EVP_MD_block_size(digest)];

	// verify the tempfilename buffer is enough to hold
	// filename_XXXXXX (+1 for null).
	if (strlen(filename)
	    > (sizeof(tempfilename) - strlen("__XXXXXX") - 1)) {
		pam_syslog(pamh, LOG_DEBUG, "Not enough buffer, bailing out");
		return PAM_AUTHTOK_ERR;
	}
	// Fetch the key from key file name.
	keyfile = fopen(keyfilename, "r");
	if (keyfile == NULL) {
		pam_syslog(pamh, LOG_DEBUG, "Unable to open key file %s",
			   keyfilename);
		return PAM_AUTHTOK_ERR;
	}
	if (fread(keybuff, 1, keybuffsize, keyfile) != keybuffsize) {
		pam_syslog(pamh, LOG_DEBUG, "Key file read failed");
		fclose(keyfile);
		return PAM_AUTHTOK_ERR;
	}
	fclose(keyfile);

	oldmask = umask(077);

	snprintf(tempfilename, sizeof(tempfilename), "%s__XXXXXX", filename);
	fd = mkstemp(tempfilename);
	if (fd == -1) {
		pam_syslog(pamh, LOG_DEBUG, "Error in creating temp file");
		err = 1;
		goto done;
	}
	pam_syslog(pamh, LOG_DEBUG, "Temporary file name is %s", tempfilename);

	pwfile = fdopen(fd, "w");
	if (pwfile == NULL) {
		err = 1;
		goto done;
	}
	umask(oldmask);

	opwfile = fopen(filename, "r");
	if (opwfile != NULL) {
		if (fstat(fileno(opwfile), &st) == -1) {
			fclose(opwfile);
			fclose(pwfile);
			err = 1;
			goto done;
		}
	} else { // Create with this settings if file is not present.
		st.st_size = 0;
		st.st_uid = 0;
		st.st_gid = 0;
		st.st_mode = 0x8000 | S_IRUSR;
	}

	if (fchown(fileno(pwfile), st.st_uid, st.st_gid) == -1) {
		if (opwfile != NULL) {
			fclose(opwfile);
		}
		fclose(pwfile);
		err = 1;
		goto done;
	}
	if (fchmod(fileno(pwfile), st.st_mode) == -1) {
		if (opwfile != NULL) {
			fclose(opwfile);
		}
		fclose(pwfile);
		err = 1;
		goto done;
	}

	opwfilesize = st.st_size;
	if (opwfilesize) {
		opwfilebuff = malloc(opwfilesize);
		if (opwfilebuff == NULL) {
			fclose(opwfile);
			fclose(pwfile);
			err = 1;
			goto done;
		}

		if (fread(opwfilebuff, 1, opwfilesize, opwfile)) {
			opwmp = (metapassstruct *)opwfilebuff;
			opwptext = malloc(opwmp->datasize + opwmp->padsize);
			if (opwptext == NULL) {
				free(opwfilebuff);
				fclose(opwfile);
				fclose(pwfile);
				err = 1;
				goto done;
			}
			pwptextlen = opwmp->datasize + forwholen + towhatlen + 3
				     + EVP_CIPHER_block_size(cipher);
			pwptext = malloc(pwptextlen);
			if (pwptext == NULL) {
				free(opwptext);
				free(opwfilebuff);
				fclose(opwfile);
				fclose(pwfile);
				err = 1;
				goto done;
			}

			// First get the hashed key to decrypt
			HMAC(digest, keybuff, keybuffsize,
			     opwfilebuff + sizeof(*opwmp), opwmp->hashsize, key,
			     &keylen);

			// Skip decryption if there is no data
			if (opwmp->datasize != 0) {
				// Do the decryption
				if (encrypt_decrypt_data(
					    pamh, 0, cipher, key, keylen,
					    opwfilebuff + sizeof(*opwmp)
						    + opwmp->hashsize,
					    opwmp->ivsize,
					    opwfilebuff + sizeof(*opwmp)
						    + opwmp->hashsize
						    + opwmp->ivsize,
					    opwmp->datasize + opwmp->padsize,
					    opwptext, &opwptextlen,
					    opwfilebuff + sizeof(*opwmp)
						    + opwmp->hashsize
						    + opwmp->ivsize
						    + opwmp->datasize
						    + opwmp->padsize,
					    &opwmp->macsize)
				    != 0) {
					pam_syslog(pamh, LOG_DEBUG,
						   "Decryption failed");
					free(pwptext);
					free(opwptext);
					free(opwfilebuff);
					fclose(opwfile);
					fclose(pwfile);
					err = 1;
					goto done;
				}
			}

			// NULL terminate it, before using it in strtok().
			opwptext[opwmp->datasize] = '\0';

			linebuff = strtok(opwptext, "\n");
			while (linebuff != NULL) {
				if ((!strncmp(linebuff, forwho, forwholen))
				    && (linebuff[forwholen] == ':')) {
					writtensize += snprintf(
						pwptext + writtensize,
						pwptextlen - writtensize,
						"%s:%s\n", forwho, towhat);
					wroteentry = 1;
				} else {
					writtensize += snprintf(
						pwptext + writtensize,
						pwptextlen - writtensize,
						"%s\n", linebuff);
				}
				linebuff = strtok(NULL, "\n");
			}
		}
		// Clear the old password related buffers here, as we are done
		// with it.
		free(opwfilebuff);
		free(opwptext);
	} else {
		pwptextlen = forwholen + towhatlen + 3
			     + EVP_CIPHER_block_size(cipher);
		pwptext = malloc(pwptextlen);
		if (pwptext == NULL) {
			if (opwfile != NULL) {
				fclose(opwfile);
			}
			fclose(pwfile);
			err = 1;
			goto done;
		}
	}

	if (opwfile != NULL) {
		fclose(opwfile);
	}

	if (wroteentry) {
		// Entry already updated,  round it off as per the CIPHER block
		pwptextlen =
			block_round(writtensize, EVP_CIPHER_block_size(cipher));
		// memset the padding bytes
		memset(pwptext + writtensize, 0, pwptextlen - writtensize);
	} else {
		// Write the new entry @ the end and round it off as per the
		// CIPHER block.
		writtensize += snprintf(pwptext + writtensize,
					pwptextlen - writtensize, "%s:%s\n",
					forwho, towhat);
		pwptextlen =
			block_round(writtensize, EVP_CIPHER_block_size(cipher));
		// memset the padding bytes
		memset(pwptext + writtensize, 0, pwptextlen - writtensize);
	}

	if (RAND_bytes(hash, EVP_MD_block_size(digest)) != 1) {
		pam_syslog(pamh, LOG_DEBUG,
			   "Hash genertion failed, bailing out");
		free(pwptext);
		fclose(pwfile);
		err = 1;
		goto done;
	}

	// Generate hash key, which will be used for encryption.
	HMAC(digest, keybuff, keybuffsize, hash, EVP_MD_block_size(digest), key,
	     &keylen);
	// Generate IV values
	if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
		pam_syslog(pamh, LOG_DEBUG,
			   "IV generation failed, bailing out");
		free(pwptext);
		fclose(pwfile);
		err = 1;
		goto done;
	}

	// Buffer to store encrypted message.
	pwctext = malloc(pwptextlen + EVP_CIPHER_block_size(cipher));
	if (pwctext == NULL) {
		pam_syslog(pamh, LOG_DEBUG, "Ctext buffer failed, bailing out");
		free(pwptext);
		fclose(pwfile);
		err = 1;
		goto done;
	}

	// Do the encryption
	if (encrypt_decrypt_data(pamh, 1, cipher, key, keylen, iv,
				 EVP_CIPHER_iv_length(cipher), pwptext,
				 pwptextlen, pwctext, &pwctextlen, mac, &maclen)
	    != 0) {
		pam_syslog(pamh, LOG_DEBUG, "Encryption failed");
		free(pwctext);
		free(pwptext);
		fclose(pwfile);
		err = 1;
		goto done;
	}

	// Update the meta password structure.
	pwmp.hashsize = EVP_MD_block_size(digest);
	pwmp.ivsize = EVP_CIPHER_iv_length(cipher);
	pwmp.datasize = writtensize;
	pwmp.padsize = pwctextlen - writtensize;
	pwmp.macsize = maclen;

	if (fwrite(&pwmp, 1, sizeof(pwmp), pwfile) != sizeof(pwmp)) {
		pam_syslog(pamh, LOG_DEBUG, "Error in writing meta data");
		err = 1;
	}
	if (fwrite(hash, 1, pwmp.hashsize, pwfile) != pwmp.hashsize) {
		pam_syslog(pamh, LOG_DEBUG, "Error in writing hash data");
		err = 1;
	}
	if (fwrite(iv, 1, pwmp.ivsize, pwfile) != pwmp.ivsize) {
		pam_syslog(pamh, LOG_DEBUG, "Error in writing IV data");
		err = 1;
	}
	if (fwrite(pwctext, 1, pwctextlen, pwfile) != pwctextlen) {
		pam_syslog(pamh, LOG_DEBUG, "Error in encrypted data");
		err = 1;
	}
	if (fwrite(mac, 1, maclen, pwfile) != maclen) {
		pam_syslog(pamh, LOG_DEBUG, "Error in writing MAC");
		err = 1;
	}

	free(pwctext);
	free(pwptext);

	if (fflush(pwfile) || fsync(fileno(pwfile))) {
		pam_syslog(
			pamh, LOG_DEBUG,
			"fflush or fsync error writing entries to special file: %s",
			tempfilename);
		err = 1;
	}

	if (fclose(pwfile)) {
		pam_syslog(pamh, LOG_DEBUG,
			   "fclose error writing entries to special file: %s",
			   tempfilename);
		err = 1;
	}

done:
	if (!err) {
		if (!rename(tempfilename, filename)) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password changed for %s in special file",
				   forwho);
		} else {
			err = 1;
		}
	}

	// Clear out the key buff.
	memset(keybuff, 0, keybuffsize);

	if (!err) {
		return PAM_SUCCESS;
	} else {
		unlink(tempfilename);
		return PAM_AUTHTOK_ERR;
	}
}


/* Password Management API's */

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	const void *item = NULL;
	const char *user = NULL;
	const char *pass_new = NULL, *pass_old = NULL;
	const char *spec_grp_name =
		get_option(pamh, "spec_grp_name", argc, argv);
	const char *spec_pass_file =
		get_option(pamh, "spec_pass_file", argc, argv);
	const char *key_file = get_option(pamh, "key_file", argc, argv);


	if (spec_grp_name == NULL || key_file == NULL) {
		return PAM_IGNORE;
	}
	if (flags & PAM_PRELIM_CHECK) {
		// send success to verify other stacked modules prelim check.
		return PAM_SUCCESS;
	}

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	// get  already read password by the stacked pam module
	// Note: If there are no previous stacked pam module which read
	// the new password, then return with AUTHTOK_ERR

	retval = pam_get_item(pamh, PAM_AUTHTOK, &item);
	if (retval != PAM_SUCCESS || item == NULL) {
		return PAM_AUTHTOK_ERR;
	}
	pass_new = item;

	struct group *grp;
	int spec_grp_usr = 0;
	// Verify whether the user belongs to special group.
	grp = pam_modutil_getgrnam(pamh, spec_grp_name);
	if (grp != NULL) {
		while (*(grp->gr_mem) != NULL) {
			if (strcmp(user, *grp->gr_mem) == 0) {
				spec_grp_usr = 1;
				break;
			}
			(grp->gr_mem)++;
		}
	}

	pam_syslog(pamh, LOG_DEBUG, "User belongs to special grp: %x",
		   spec_grp_usr);

	if (spec_grp_usr) {
		// verify the new password is acceptable.
		if (strlen(pass_new) > MAX_SPEC_GRP_PASS_LENGTH
		    || strlen(user) > MAX_SPEC_GRP_USER_LENGTH) {
			pam_syslog(
				pamh, LOG_ERR,
				"Password length (%x) / User name length (%x) not acceptable",
				strlen(pass_new), strlen(user));
			pass_new = NULL;
			return PAM_NEW_AUTHTOK_REQD;
		}
		if (spec_pass_file == NULL) {
			spec_pass_file = DEFAULT_SPEC_PASS_FILE;
			pam_syslog(
				pamh, LOG_ERR,
				"Using default special password file name :%s",
				spec_pass_file);
		}
		lock_pwdf();
		retval = update_pass_special_file(
			pamh, key_file, spec_pass_file, user, pass_new);
		unlock_pwdf();
		return retval;
	}

	return PAM_SUCCESS;
}

/* end of module definition */
