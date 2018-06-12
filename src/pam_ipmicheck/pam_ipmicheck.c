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

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#define MAX_SPEC_GRP_PASS_LENGTH 20
#define MAX_SPEC_GRP_USER_LENGTH 16


/*
 * This module is intended to verify special group user password matches the
 * restrictions needed.
 *
 * Note: Other than for pam_chauthtok(), pam_ipmicheck module  should not be
 * used for other purpose like authentication, session & account management.
 * This module has to be used along with pam_ipmisave module, which will save
 * the passwords of the special group users.
 */


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

/* Password Management API's */

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	const void *item = NULL;
	const char *user = NULL;
	const char *pass_new = NULL, *pass_old = NULL;
	const char *spec_grp_name =
		get_option(pamh, "spec_grp_name", argc, argv);

	pam_syslog(pamh, LOG_DEBUG, "Special group name is %s", spec_grp_name);

	if (spec_grp_name == NULL) {
		return PAM_IGNORE;
	}
	if (flags & PAM_PRELIM_CHECK) {
		// send success to verify other stacked modules prelim check.
		pam_syslog(pamh, LOG_DEBUG, "PRELIM_CHECK Called");
		return PAM_SUCCESS;
	}

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		return retval;
	}


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

	if (spec_grp_usr) {
		// Read new password.
		// Note: Subsequent modules must try to use stacked password
		// before reading it again. Must use "try_first_pass" to try
		// the stacked module password
		retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass_new, NULL);
		if (retval != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ALERT,
				   "password - unable to get new password");
			return retval;
		}


		// verify the new password is acceptable.
		if (strlen(pass_new) > MAX_SPEC_GRP_PASS_LENGTH
		    || strlen(user) > MAX_SPEC_GRP_USER_LENGTH) {
			pam_syslog(
				pamh, LOG_ERR,
				"Password length (%x) / User name length (%x) not acceptable",
				strlen(pass_new), strlen(user));
			pass_new = pass_old = NULL;
			return PAM_NEW_AUTHTOK_REQD;
		}
	}

	return PAM_SUCCESS;
}

/* end of module definition */
