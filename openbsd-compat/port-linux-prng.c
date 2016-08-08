/* $Id: port-linux.c,v 1.11.4.2 2011/02/04 00:43:08 djm Exp $ */

/*
 * Copyright (c) 2011 Jan F. Chadima <jchadima@redhat.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Linux-specific portability code - prng support
 */

#include "includes.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "log.h"
#include "xmalloc.h"
#include "servconf.h"
#include "port-linux.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"

void
linux_seed(void)
{
	int len;
	char *env = getenv("SSH_USE_STRONG_RNG");
	char *random = "/dev/random";
	size_t ienv, randlen = 14;

	if (!env || !strcmp(env, "0"))
		random = "/dev/urandom";
	else if ((ienv = atoi(env)) > randlen)
		randlen = ienv;

	errno = 0;
	if ((len = RAND_load_file(random, randlen)) != randlen) {
		if (errno)
			fatal ("cannot read from %s, %s", random, strerror(errno));
		else
			fatal ("EOF reading %s", random);
	}
}
