/*
 * Copyright (c) 2005-2008 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING.GPL included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <conio.h>
#endif

#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-data.h>

static char *prompt_prog = NULL;

#if defined(_WIN32)

static
int
prompt_callback(char *prompt_type, char *prompt, char *input, int input_size) {
	return -1;
}

#else

static
int
prompt_callback(char *prompt_type, char *prompt, char *input, int input_size) {
	int status;
	pid_t pid = -1;
	int fds[2] = {-1, -1};
	int r = 0;
	int rc;

	/*
	 * Make sure we don't reuse input
	 */
	if (input) {
		memset (input, 0, input_size);
	}

	if (prompt_prog == NULL) {
		rc = -EINVAL;
		goto out;
	}

	if (pipe (fds) == -1) {
		rc = -errno;
		goto out;
	}

	if ((pid = fork ()) == -1) {
		rc = -errno;
		goto out;
	}

	if (pid == 0) {
		pkcs11h_forkFixup ();

		close (fds[0]);
		fds[0] = -1;

		if (dup2 (fds[1], 1) == -1) {
			exit (1);
		}

		close (fds[1]);
		fds[1] = -1;

		execl (
			prompt_prog,
			prompt_prog,
			"-t",
			prompt_type,
			prompt,
			NULL
		);

		exit (1);
	}

	close (fds[1]);
	fds[1] = -1;

	while (
		(r=waitpid (pid, &status, 0)) == 0 ||
		(r == -1 && errno == EINTR)
	);

	if (r == -1) {
		rc = -errno;
		goto out;
	}

	if (!WIFEXITED (status)) {
		rc = -EFAULT;
		goto out;
	}

	if (WEXITSTATUS (status) != 0) {
		rc = -EIO;
		goto out;
	}
	
	if (input) {
		if ((r = read (fds[0], input, input_size)) == -1) {
			rc = -errno;
			goto out;
		}

		input[r] = '\0';

		if (strlen (input) > 0 && input[strlen (input)-1] == '\n') {
			input[strlen (input)-1] = '\0';
		}
	}

	rc = 0;

out:
	if (rc != 0) {
		if (input) {
			memset (input, 0, input_size);
		}
	}

	if (fds[0] != -1) {
		close (fds[0]);
		fds[0] = -1;
	}

	if (fds[1] != -1) {
		close (fds[1]);
		fds[1] = -1;
	}

	return rc;
}
#endif

static
CK_RV
my_list (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic
) {
	pkcs11h_data_id_list_t data_id_list = NULL;
	pkcs11h_data_id_list_t entry;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if (
		(rv = pkcs11h_data_enumDataObjects (
			token_id,
			fPublic,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			&data_id_list
		)) != CKR_OK
	) {
		goto cleanup;
	}

	for (entry = data_id_list;entry != NULL;entry = entry->next) {
		printf ("A=%s, L=%s\n", entry->application, entry->label);
	}

	rv = CKR_OK;

cleanup:

	if (data_id_list != NULL) {
		pkcs11h_data_freeDataIdList (data_id_list);
	}
	
	return rv;
}

static
CK_RV
my_export (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel,
	IN const char * const szFile
) {
	FILE *fp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	CK_RV rv = CKR_FUNCTION_FAILED;

	if (!strcmp (szFile, "-")) {
		fp = stdout;
	}
	else if ((fp = fopen (szFile, "wb")) == NULL) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	if (
		(rv = pkcs11h_data_get (
			token_id,
			fPublic,
			szApplication,
			szLabel,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			NULL,
			&blob_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	blob = (unsigned char *)malloc (blob_size);

	if (
		(rv = pkcs11h_data_get (
			token_id,
			FALSE,
			szApplication,
			szLabel,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			blob,
			&blob_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	if (fwrite (blob, 1, blob_size, fp) != blob_size) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:

	if (fp != NULL) {
		if (strcmp (szFile, "-")) {
			fclose (fp);
		}
	}

	if (blob != NULL) {
		free (blob);
	}
	
	return rv;
}

static
CK_RV
my_import (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel,
	IN const char * const szFile
) {
	FILE *fp = NULL;
	unsigned char blob[100*1024];
	int blob_size;
	int r;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if (!strcmp (szFile, "-")) {
		fp = stdin;
	}
	else if ((fp = fopen (szFile, "rb")) == NULL) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	if ((r = fread (blob, 1, sizeof (blob), fp)) == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}
	blob_size = r;

	if (
		(rv = pkcs11h_data_put (
			token_id,
			fPublic,
			szApplication,
			szLabel,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			blob,
			blob_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:

	if (fp != NULL) {
		if (strcmp (szFile, "-")) {
			fclose (fp);
		}
	}

	return rv;
}

static
CK_RV
my_remove (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel
) {
	return pkcs11h_data_del (
		token_id,
		fPublic,
		szApplication,
		szLabel,
		NULL,
		PKCS11H_PROMPT_MASK_ALLOW_ALL
	);
}

static
void
_pkcs11h_hooks_log (
	IN void * const global_data,
	IN const unsigned flags,
	IN const char * const format,
	IN va_list args
) {
	(void)global_data;
	(void)flags;

	vfprintf (stderr, format, args);
	fprintf (stderr, "\n");
}

static
PKCS11H_BOOL
_pkcs11h_hooks_token_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
) {
	PKCS11H_BOOL wait_for_token = *(PKCS11H_BOOL *)global_data;
	char buf[1024];
	char prompt[1024];
	PKCS11H_BOOL fValidInput = FALSE;
	PKCS11H_BOOL fRet = FALSE;

	(void)user_data;
	(void)retry;

	while (wait_for_token && !fValidInput) {
		snprintf (prompt, sizeof (prompt), "Please insert token '%s' 'ok' or 'cancel': ", token->display);
		if (prompt_prog == NULL) {
			fprintf (stderr, "%s", prompt);
			if (fgets (buf, sizeof (buf), stdin) == NULL) {}
			buf[sizeof (buf)-1] = '\0';
			fflush (stdin);
		}
		else {
			if (prompt_callback ("text", prompt, buf, sizeof (buf))) {
				strcpy (buf, "cancel");
			}
		}

		if (buf[0] != '\0' && buf[strlen (buf)-1] == '\n') {
			buf[strlen (buf)-1] = '\0';
		}
		if (buf[0] != '\0' && buf[strlen (buf)-1] == '\r') {
			buf[strlen (buf)-1] = '\0';
		}

		if (!strcmp (buf, "ok")) {
			fValidInput = TRUE;
			fRet = TRUE;
		}
		else if (!strcmp (buf, "cancel")) {
			fValidInput = TRUE;
		}
	}

	return fRet; 
}

static
PKCS11H_BOOL
_pkcs11h_hooks_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
) {
	char prompt[1024];

	(void)global_data;
	(void)user_data;
	(void)retry;

	snprintf (prompt, sizeof (prompt), "Please enter '%s' PIN or 'cancel': ", token->display);

#if defined(_WIN32)
	{
		size_t i = 0;
		char c;
		while (i < pin_max-1 && (c = getch ()) != '\r') {
			pin[i++] = c;
		}
		pin[i] = '\0';
	}

	fprintf (stderr, "\n");
#else
	if (prompt_prog == NULL) {
		char *p = getpass (prompt);
		strncpy (pin, p, pin_max);
		pin[pin_max-1] = '\0';
	}
	else {
		if (prompt_callback ("password", prompt, pin, pin_max)) {
			strcpy (pin, "cancel");
		}
	}
#endif

	return strcmp (pin, "cancel") != 0;
}

int
main (
	int argc,
	char *argv[]
) {
	pkcs11h_token_id_t token_id = NULL;
	PKCS11H_BOOL fUsageOK = TRUE;
	CK_RV rv = CKR_FUNCTION_FAILED;

	enum {
		OPT_ADD_PROVIDER,
		OPT_TOKEN,
		OPT_APPLICATION,
		OPT_LABEL,
		OPT_FILE,
		OPT_CMD,
		OPT_TOKEN_WAIT,
		OPT_PUBLIC,
		OPT_PROMPT_PROG,
		OPT_VERBOSE,
		OPT_VERSION,
		OPT_HELP
	};
	enum {
		CMD_UNKNOWN,
		CMD_TOKENS,
		CMD_LIST,
		CMD_IMPORT,
		CMD_EXPORT,
		CMD_REMOVE
	} cmd = CMD_UNKNOWN;

	#define MAX_OBJECTS 100
	struct {
		char *szApplication;
		char *szLabel;
		char *szFile;
	} objects[MAX_OBJECTS];
	int nObjects = 0;

	char *szToken = NULL;
	PKCS11H_BOOL wait_for_token = FALSE;
	PKCS11H_BOOL fPublic = FALSE;

	static struct option long_options[] = {
		{ "add-provider", required_argument, NULL, OPT_ADD_PROVIDER },
		{ "token", required_argument, NULL, OPT_TOKEN },
		{ "application", required_argument, NULL, OPT_APPLICATION },
		{ "label", required_argument, NULL, OPT_LABEL },
		{ "file", required_argument, NULL, OPT_FILE },
		{ "cmd", required_argument, NULL, OPT_CMD },
		{ "token-wait", no_argument, NULL, OPT_TOKEN_WAIT },
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "public", no_argument, NULL, OPT_PUBLIC },
		{ "prompt-prog", required_argument, NULL, OPT_PROMPT_PROG },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int long_options_ret;
	int i;

	/*
	 * For edge condition, when
	 * --file is not specified
	 *  all must me initialized.
	 */
	memset (objects, 0, sizeof (objects));

	if (
		(rv = pkcs11h_initialize ()) != CKR_OK ||
		(rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK
	) {
		goto cleanup;
	}

	pkcs11h_setLogLevel (PKCS11H_LOG_QUIET);

	if (
		(rv = pkcs11h_setTokenPromptHook (_pkcs11h_hooks_token_prompt, &wait_for_token)) != CKR_OK ||
		(rv = pkcs11h_setPINPromptHook (_pkcs11h_hooks_pin_prompt, NULL)) != CKR_OK
	) {
		goto cleanup;
	}

	while (
		nObjects < MAX_OBJECTS-1 &&
		(long_options_ret = getopt_long (argc, argv, "", long_options, NULL)) != -1
	) {
		switch (long_options_ret) {
			case OPT_ADD_PROVIDER:
				if (
					(rv = pkcs11h_addProvider (
						optarg,
						optarg,
						TRUE,
						0,
						PKCS11H_SLOTEVENT_METHOD_AUTO,
						0,
						FALSE
					)) != CKR_OK
				) {
					fprintf (stderr, "Cannot add provider '%s'\n", optarg); 
				}
			break;
			case OPT_TOKEN:
				szToken = strdup (optarg);
			break;
			case OPT_APPLICATION:
				if (objects[nObjects].szApplication != NULL) {
					nObjects++;
				}
				objects[nObjects].szApplication = strdup (optarg);
			break;
			case OPT_LABEL:
				if (objects[nObjects].szLabel != NULL) {
					nObjects++;
				}
				objects[nObjects].szLabel = strdup (optarg);
			break;
			case OPT_FILE:
				objects[nObjects].szFile = strdup (optarg);
				nObjects++;
			break;
			case OPT_CMD:
				if (!strcmp (optarg, "tokens")) {
					cmd = CMD_TOKENS;
				}
				else if (!strcmp (optarg, "list")) {
					cmd = CMD_LIST;
				}
				else if (!strcmp (optarg, "export")) {
					cmd = CMD_EXPORT;
				}
				else if (!strcmp (optarg, "import")) {
					cmd = CMD_IMPORT;
				}
				else if (!strcmp (optarg, "remove")) {
					cmd = CMD_REMOVE;
				}
				else {
					fUsageOK = FALSE;
				}
			break;
			case OPT_TOKEN_WAIT:
				wait_for_token = TRUE;
			break;
			case OPT_PUBLIC:
				fPublic = TRUE;
			break;
#if !defined(_WIN32)
			case OPT_PROMPT_PROG:
				prompt_prog = strdup (optarg);
			break;
#endif
			case OPT_VERBOSE:
				pkcs11h_setLogLevel (PKCS11H_LOG_DEBUG2);
			break;
			case OPT_VERSION:
				printf (
					(
						"%s %s\n"
						"Written by Alon Bar-Lev\n"
						"\n"
						"Copyright (C) 2005-2006 Alon Bar-Lev.\n"
						"This is free software; see the source for copying conditions.\n"
						"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
					),
					PACKAGE,
					PACKAGE_VERSION
				);
				exit (1);
			break;
			default:
				fUsageOK = FALSE;
			break;
		}
	}

	/*
	 * For edge condition where
	 * --file was not provided
	 */
	if (objects[nObjects].szApplication != NULL || objects[nObjects].szLabel != NULL) {
		nObjects++;
	}

	switch (cmd) {
		case CMD_TOKENS:
		break;
		case CMD_LIST:
			if (fUsageOK && szToken == NULL) {
				fUsageOK = FALSE;
			}
		break;
		case CMD_IMPORT:
			if (fUsageOK && szToken == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && nObjects != 1) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szApplication == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szLabel == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szFile == NULL) {
				objects[0].szFile = "-";
			}
		break;
		case CMD_EXPORT:
			if (fUsageOK && nObjects == 0) {
				fUsageOK = FALSE;
			}
			for (i=0;i<nObjects;i++) {
				if (fUsageOK && objects[i].szApplication == NULL) {
					fUsageOK = FALSE;
				}
				if (fUsageOK && objects[i].szLabel == NULL) {
					fUsageOK = FALSE;
				}
				if (fUsageOK && objects[i].szFile == NULL) {
					objects[i].szFile = "-";
				}
			}
		break;
		case CMD_REMOVE:
			if (fUsageOK && szToken == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && nObjects != 1) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szApplication == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szLabel == NULL) {
				fUsageOK = FALSE;
			}
			if (fUsageOK && objects[0].szFile != NULL) {
				fUsageOK = FALSE;
			}
		break;
		default:
			fUsageOK = FALSE;
		break;
	}

	if (!fUsageOK) {
		fprintf (
			stderr,
			(
			 	"usage:\n"
				"%s\n"
				"        --help                        This help\n"
				"        --verbose                     Enable logging\n"
				"        --add-provider=lib            PKCS#11 provider library\n"
				"        --public                      Objects are not private\n"
				"        --prompt-prog                 Register prompt program\n"
				"        --token-wait                  Wait for the token\n"
				"        --cmd=tokens                  List available tokens\n"
				"        --cmd=list                    List objects\n"
				"                --token=              Token id\n"
				"        --cmd=export                  Export object\n"
				"                [--token=]            Token id\n"
				"                --application=        Application name\n"
				"                --label=              Label\n"
				"                [--file=]             Target file or stdout\n"
				"                [\n"
				"                 --application=\n"
				"                 --label=\n"
				"                 --file=\n"
				"                ]...\n"
				"        --cmd=import                  Import object\n"
				"                --token=              Token id\n"
				"                --application=        Application name\n"
				"                --label=              Label\n"
				"                [--file=]             Source file or stdin\n"
				"        --cmd=remove                  Remove object\n"
				"                --token=              Token id\n"
				"                --application=        Application name\n"
				"                --label=              Label\n"
			),
			argv[0]
		);
		exit (2);
	}

	if (szToken != NULL) {
		if (
			(rv = pkcs11h_token_deserializeTokenId (
				&token_id,
				szToken
			)) != CKR_OK
		) {
			goto cleanup;
		}
	}

	if (szToken == NULL && cmd != CMD_TOKENS) {
		PKCS11H_BOOL fTokenFirst = TRUE;
		
		do {
			pkcs11h_token_id_list_t tokens = NULL;
			pkcs11h_token_id_list_t current;
			int id = 0;

			if (
				(rv = pkcs11h_token_enumTokenIds (
					PKCS11H_ENUM_METHOD_RELOAD,
					&tokens
				)) != CKR_OK
			) {
				goto retry;
			}

			if (tokens != NULL && tokens->next != NULL) {
				char prompt[2048];
				char buf[1024];

				strcpy (
					prompt,
					"Please select token:\n"
				);
				for (current = tokens, id=0;current != NULL;current = current->next, id++) {
					snprintf (
						prompt+strlen (prompt),
						sizeof (prompt)-strlen (prompt),
						"%02d %s - %s\n",
						id,
						current->token_id->manufacturerID,
						current->token_id->label
					);
				}
				if (prompt_prog == NULL) {
					fprintf (stderr, "%s> ", prompt);
					if (fgets (buf, sizeof (buf), stdin) == NULL) {}
					fflush (stdin);
				}
				else {
					if (prompt_callback ("text", prompt, buf, sizeof (buf))) {
						strcpy (buf, "cancel");
					}
				}

				if (buf[0] != '\0' && buf[strlen (buf)-1] == '\n') {
					buf[strlen (buf)-1] = '\0';
				}
				if (buf[0] != '\0' && buf[strlen (buf)-1] == '\r') {
					buf[strlen (buf)-1] = '\0';
				}

				if (!strcmp (buf, "cancel")) {
					rv = CKR_FUNCTION_CANCELED;
					goto retry;
				}

				if (sscanf (buf, "%d", &id) != 1) {
					rv = CKR_ARGUMENTS_BAD;
					goto retry;
				}
			}

			current = tokens;
			while (current != NULL && id>0) {
				current = current->next;
				id--;
			}

			if (current == NULL) {
				rv = CKR_SLOT_ID_INVALID;
				goto retry;
			}

			if (
				(rv = pkcs11h_token_duplicateTokenId (
					&token_id,
					current->token_id
				)) != CKR_OK
			) {
				goto retry;
			}

			wait_for_token = FALSE;
			rv = CKR_OK;

		retry:

			if (tokens != NULL) {
				pkcs11h_token_freeTokenIdList (tokens);
				tokens = NULL;
			}

			if (
				wait_for_token &&
				rv == CKR_SLOT_ID_INVALID
			) {
				rv = CKR_OK;

				if (fTokenFirst) {
					if (prompt_prog == NULL) {
						fprintf (
							stderr,
							"Please insert token...\n"
						);
					}
					else {
						prompt_callback ("none", "Please insert token...", NULL, 0);
					}
					fTokenFirst = FALSE;
				}
#if defined(_WIN32)
				Sleep (1000);
#else
				sleep (1);
#endif
			}

			if (rv != CKR_OK) {
				goto cleanup;
			}
		} while (wait_for_token);
	}

	switch (cmd) {
		case CMD_TOKENS:
		{
			pkcs11h_token_id_list_t token_id_list = NULL;
			pkcs11h_token_id_list_t i = NULL;

			if (
				pkcs11h_token_enumTokenIds (
					PKCS11H_ENUM_METHOD_CACHE_EXIST,
					&token_id_list
				) == CKR_OK
			) {
				for (i=token_id_list;i!=NULL;i=i->next) {
					char *ser = NULL;
					size_t ser_size = 0;

					if (
						pkcs11h_token_serializeTokenId (
							NULL,
							&ser_size,
							i->token_id
						) == CKR_OK &&
						(ser = (char *)malloc (ser_size)) != NULL &&
						pkcs11h_token_serializeTokenId (
							ser,
							&ser_size,
							i->token_id
						) == CKR_OK
					) {
						printf (
							"manufacturerID='%s', label='%s', id='%s'\n",
							i->token_id->manufacturerID,
							i->token_id->label,
							ser
						);
					}

					if (ser != NULL) {
						free (ser);
					}
				}

				pkcs11h_token_freeTokenIdList (token_id_list);
			}
		}
		break;
		case CMD_LIST:
			rv = my_list (
				token_id,
				fPublic
			);
		break;
		case CMD_EXPORT:
			for (i=0;i<nObjects;i++) {
				rv = my_export (
					token_id,
					fPublic,
					objects[i].szApplication,
					objects[i].szLabel,
					objects[i].szFile
				);
			}
		break;
		case CMD_IMPORT:
			my_remove (
				token_id,
				fPublic,
				objects[0].szApplication,
				objects[0].szLabel
			);
			rv = my_import (
				token_id,
				fPublic,
				objects[0].szApplication,
				objects[0].szLabel,
				objects[0].szFile
			);
		break;
		case CMD_REMOVE:
			rv = my_remove (
				token_id,
				fPublic,
				objects[0].szApplication,
				objects[0].szLabel
			);
		break;
		case CMD_UNKNOWN:
		break;
	}

cleanup:

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	pkcs11h_terminate ();

	if (rv == CKR_OK) {
		exit (0);
	}
	else {
		fprintf (stderr, "failed rv=%08x-%s\n", (unsigned)rv, pkcs11h_getMessage (rv));
		exit (1);
	}

	/*Make compiler happy*/
	return 0;
}
