/* $OpenBSD: auth-krb5.c,v 1.20 2013/07/20 01:55:13 djm Exp $ */
/*
 *    Kerberos v5 authentication and ticket-passing routines.
 *
 * $FreeBSD: src/crypto/openssh/auth-krb5.c,v 1.6 2001/02/13 16:58:04 assar Exp $
 */
/*
 * Copyright (c) 2002 Daniel Kouril.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <pwd.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh1.h"
#include "packet.h"
#include "log.h"
#include "buffer.h"
#include "servconf.h"
#include "uidswap.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"

#ifdef KRB5
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <krb5.h>
#include <profile.h>

extern ServerOptions	 options;

int
ssh_krb5_kuserok(krb5_context krb5_ctx, krb5_principal krb5_user, const char *client,
                 int k5login_exists)
{
	if (options.use_kuserok || !k5login_exists)
		return krb5_kuserok(krb5_ctx, krb5_user, client);
	else {
		char kuser[65];

		if (krb5_aname_to_localname(krb5_ctx, krb5_user, sizeof(kuser), kuser))
			return 0;
		return strcmp(kuser, client) == 0;
	}
}

static int
krb5_init(void *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	if (authctxt->krb5_ctx == NULL) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		if (problem)
			return (problem);
	}
	return (0);
}

int
auth_krb5_password(Authctxt *authctxt, const char *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = NULL;
	const char *ccache_type;
	int len;
	char *client, *platform_client;
	const char *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	if (problem)
		goto out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	if (problem)
		goto out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	     krb5_mcc_ops.prefix, NULL, &ccache);
# else
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	if (problem)
		goto out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	if (problem)
		goto out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, NULL);

	temporarily_use_uid(authctxt->pw);

	if (problem)
		goto out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	     krb5_fcc_ops.prefix, NULL, &authctxt->krb5_fwd_ccache);
# else
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	if (problem)
		goto out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = NULL;
	if (problem)
		goto out;

#else
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (char *)password, NULL, NULL, 0, NULL, NULL);
	if (problem)
		goto out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, NULL, NULL,
	    KRB5_NT_SRV_HST, &server);
	if (problem)
		goto out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    NULL, NULL, NULL);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	if (problem)
		goto out;

	/* Use !options.use_kuserok here to make ssh_krb5_kuserok() not
	 * depend on the existance of .k5login */
	if (!ssh_krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user, authctxt->pw->pw_name, !options.use_kuserok)) {
		problem = -1;
		goto out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx, &authctxt->krb5_fwd_ccache);
	if (problem)
		goto out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache,
				     authctxt->krb5_user);
	if (problem)
		goto out;

	problem= krb5_cc_store_cred(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache,
				 &creds);
	if (problem)
		goto out;
#endif

	ccache_type = krb5_cc_get_type(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
	authctxt->krb5_ticket_file = (char *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	if (authctxt->krb5_ticket_file[0] == ':')
		authctxt->krb5_ticket_file++;

	len = strlen(authctxt->krb5_ticket_file) + strlen(ccache_type) + 2;
	authctxt->krb5_ccname = xmalloc(len);

#ifdef USE_CCAPI
	snprintf(authctxt->krb5_ccname, len, "API:%s",
	    authctxt->krb5_ticket_file);
#else
	snprintf(authctxt->krb5_ccname, len, "%s:%s",
	    ccache_type, authctxt->krb5_ticket_file);
#endif

	if (strcmp(ccache_type, "DIR") == 0) {
		char *p;
		p = strrchr(authctxt->krb5_ccname, '/');
		if (p)
			*p = '\0';
	}


#ifdef USE_PAM
	if (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	free(platform_client);

	if (problem) {
		if (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		if (authctxt->krb5_ctx != NULL && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
 			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} else
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		if (options.kerberos_or_local_passwd)
			return (-1);
		else
			return (0);
	}
	return (authctxt->valid ? 1 : 0);
}

void
krb5_cleanup_proc(Authctxt *authctxt)
{
	struct stat krb5_ccname_stat;
	char krb5_ccname[128], *krb5_ccname_dir_start, *krb5_ccname_dir_end;

	debug("krb5_cleanup_proc called");
	if (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = NULL;

		strncpy(krb5_ccname, authctxt->krb5_ccname, sizeof(krb5_ccname) - 10);
		krb5_ccname_dir_start = strchr(krb5_ccname, ':') + 1;
		*krb5_ccname_dir_start++ = '\0';
		if (strcmp(krb5_ccname, "DIR") == 0) {

			strcat(krb5_ccname_dir_start, "/primary");

			if (stat(krb5_ccname_dir_start, &krb5_ccname_stat) == 0) {
				if (unlink(krb5_ccname_dir_start) == 0) {
					krb5_ccname_dir_end = strrchr(krb5_ccname_dir_start, '/');
					*krb5_ccname_dir_end = '\0';
					if (rmdir(krb5_ccname_dir_start) == -1)
						debug("cache dir '%s' remove failed: %s", krb5_ccname_dir_start, strerror(errno));
				}
				else
					debug("cache primary file '%s', remove failed: %s",
						krb5_ccname_dir_start, strerror(errno)
						);
			}
		}
	}
	if (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = NULL;
	}
	if (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = NULL;
	}
}

int
ssh_asprintf_append(char **dsc, const char *fmt, ...) {
	char *src, *old;
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vasprintf(&src, fmt, ap);
	va_end(ap);

	if (i == -1 || src == NULL)
		return -1;

	old = *dsc;

	i = asprintf(dsc, "%s%s", *dsc, src);
	if (i == -1 || src == NULL) {
		free(src);
		return -1;
	}

	free(old);
	free(src);

	return i;
}

int
ssh_krb5_expand_template(char **result, const char *template) {
	char *p_n, *p_o, *r, *tmp_template;

	if (template == NULL)
		return -1;

	tmp_template = p_n = p_o = xstrdup(template);
	r = xstrdup("");

	while ((p_n = strstr(p_o, "%{")) != NULL) {

		*p_n++ = '\0';
		if (ssh_asprintf_append(&r, "%s", p_o) == -1)
			goto cleanup;

		if (strncmp(p_n, "{uid}", 5) == 0 || strncmp(p_n, "{euid}", 6) == 0 ||
			strncmp(p_n, "{USERID}", 8) == 0) {
			p_o = strchr(p_n, '}') + 1;
			if (ssh_asprintf_append(&r, "%d", geteuid()) == -1)
				goto cleanup;
			continue;
		}
		else if (strncmp(p_n, "{TEMP}", 6) == 0) {
			p_o = strchr(p_n, '}') + 1;
			if (ssh_asprintf_append(&r, "/tmp") == -1)
				goto cleanup;
			continue;
		} else {
			p_o = strchr(p_n, '}') + 1;
			p_o = '\0';
			debug("%s: unsupported token %s in %s", __func__, p_n, template);
			/* unknown token, fallback to the default */
			goto cleanup;
		}
	}

	if (ssh_asprintf_append(&r, "%s", p_o) == -1)
		goto cleanup;

	*result = r;
	free(tmp_template);
	return 0;

cleanup:
	free(r);
	free(tmp_template);
	return -1;
}

krb5_error_code
ssh_krb5_get_cctemplate(krb5_context ctx, char **ccname) {
	profile_t p;
	int ret = 0;
	char *value = NULL;

	ret = krb5_get_profile(ctx, &p);
	if (ret)
		return ret;

	ret = profile_get_string(p, "libdefaults", "default_ccache_name", NULL, NULL, &value);
	if (ret)
		return ret;

	ret = ssh_krb5_expand_template(ccname, value);

	return ret;
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	int tmpfd, ret, oerrno;
	char *ccname;
#ifdef USE_CCAPI
	char cctemplate[] = "API:krb5cc_%d";
#else
	mode_t old_umask;
	char cctemplate[] = "FILE:/tmp/krb5cc_%d_XXXXXXXXXX";

#endif

	ret = ssh_krb5_get_cctemplate(ctx, &ccname);

	if (ret) {
		ret = asprintf(&ccname, cctemplate, geteuid());
		if (ret == -1)
			return ENOMEM;
		old_umask = umask(0177);
		tmpfd = mkstemp(ccname + strlen("FILE:"));
		oerrno = errno;
		umask(old_umask);
		if (tmpfd == -1) {
			logit("mkstemp(): %.100s", strerror(oerrno));
			return oerrno;
		}

		if (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
			oerrno = errno;
			logit("fchmod(): %.100s", strerror(oerrno));
			close(tmpfd);
			return oerrno;
		}
		close(tmpfd);
	}
	debug("%s: Setting ccname to %s", __func__, ccname);

	return (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
