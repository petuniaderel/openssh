/*
 * Copyright (c) 2008, Jamie Beverly. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jamie Beverly ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Jamie Beverly OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of Jamie Beverly.
 */


#include "includes.h"
#include "config.h"

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include "ssh.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>

#include "userauth_pubkey_from_id.h"
#include "identity.h"

u_char * session_id2 = NULL;
uint8_t session_id_len = 0;

u_char *
session_id2_gen()
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;

    rnd = arc4random();
    session_id_len = (uint8_t) rnd;

    cookie = calloc(1,session_id_len);

    for (i = 0; i < session_id_len; i++) {
        if (i % 4 == 0) {
            rnd = arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    return cookie;
}

/* 
 * Added by Jamie Beverly, ensure socket fd points to a socket owned by the user 
 * A cursory check is done, but to avoid race conditions, it is necessary 
 * to drop effective UID when connecting to the socket. 
 *
 * If the cause of error is EACCES, because we verified we would not have that 
 * problem initially, we can safely assume that somebody is attempting to find a 
 * race condition; so a more "direct" log message is generated.
 */

int
ssh_get_authentication_socket_for_uid(uid_t uid)
{
	const char *authsocket;
	int sock;
	struct sockaddr_un sunaddr;
	struct stat sock_st;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	if (!authsocket)
		return -1;

	/* Advisory only; seteuid ensures no race condition; but will only log if we see EACCES */
	if( stat(authsocket,&sock_st) == 0) {
		if(uid != 0 && sock_st.st_uid != uid) {
			fatal("uid %lu attempted to open an agent socket owned by uid %lu", (unsigned long) uid, (unsigned long) sock_st.st_uid);
			return -1;
		}
	}

	/* 
	 * Ensures that the EACCES tested for below can _only_ happen if somebody 
	 * is attempting to race the stat above to bypass authentication.
	 */
	if( (sock_st.st_mode & S_IWUSR) != S_IWUSR || (sock_st.st_mode & S_IRUSR) != S_IRUSR) {
		error("ssh-agent socket has incorrect permissions for owner");
		return -1;
	}

	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	/* close on exec */
	if (fcntl(sock, F_SETFD, 1) == -1) {
		close(sock);
		return -1;
	}

	errno = 0; 
	/* To ensure a race condition is not used to circumvent the stat
	   above, we will temporarily drop UID to the caller */
	if (seteuid(uid) == -1) {
		close(sock);
		error("seteuid(%lu) failed", (unsigned long) uid);
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&sunaddr, sizeof sunaddr) < 0) {
		close(sock);
		sock = -1;
		if(errno == EACCES)
			fatal("MAJOR SECURITY WARNING: uid %lu made a deliberate and malicious attempt to open an agent socket owned by another user", (unsigned long) uid);
	}

	seteuid(0); /* we now continue the regularly scheduled programming */

	return sock;
}

AuthenticationConnection *
ssh_get_authentication_connection_for_uid(uid_t uid)
{
	AuthenticationConnection *auth;
	int sock;

	sock = ssh_get_authentication_socket_for_uid(uid);

	/*
	 * Fail if we couldn't obtain a connection.  This happens if we
	 * exited due to a timeout.
	 */
	if (sock < 0)
		return NULL;

	auth = xmalloc(sizeof(*auth));
	auth->fd = sock;
	buffer_init(&auth->identities);
	auth->howmany = 0;

	return auth;
}

int
find_authorized_keys(uid_t uid)
{
    Identity *id;
    Key *key;
    AuthenticationConnection *ac;
    char *comment;
    uint8_t retval = 0;

    OpenSSL_add_all_digests();
    session_id2 = session_id2_gen();

    if ((ac = ssh_get_authentication_connection_for_uid(uid))) {
        verbose("Contacted ssh-agent of user %s (%u)", getpwuid(uid)->pw_name, uid);
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2)) 
        {
            if(key != NULL) {
                id = xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(id)) {
                    retval = 1;
                }
                free(id->filename);
                key_free(id->key);
                free(id);
                if(retval == 1)
                    break;
            }
        }
        ssh_close_authentication_connection(ac);
    }
    else {
        verbose("No ssh-agent could be contacted");
    }
    free(session_id2);
    EVP_cleanup();
    return retval;
}

