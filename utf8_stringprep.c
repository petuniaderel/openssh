/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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
 * This is a simple RFC3454 stringprep profile to sanitise UTF-8 strings
 * from untrusted sources.
 *
 * It is intended to be used prior to display of untrusted strings only.
 * It should not be used for logging because of bi-di ambiguity. It
 * should also not be used in any case where lack of normalisation may
 * cause problems.
 *
 * This profile uses the prohibition and mapping tables from RFC3454
 * (listed below) but the unassigned character table has been updated to
 * Unicode 6.2. It uses a local whitelist of whitespace characters (\n,
 * \a and \t). Unicode normalisation and bi-di testing are not used.
 *
 * XXX: implement bi-di handling (needed for logs)
 * XXX: implement KC normalisation (needed for passing to libs/syscalls)
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include "misc.h"

struct u32_range {
	u_int32_t lo, hi;  /* Inclusive */
};

#include "stringprep-tables.c"

/* Returns 1 if code 'c' appears in the table or 0 otherwise */
static int
code_in_table(u_int32_t c, const struct u32_range *table, size_t tlen)
{
	const struct u32_range *e, *end = (void *)(tlen + (char *)table);

	for (e = table; e < end; e++) {
		if (c >= e->lo && c <= e->hi)
			return 1;
	}
	return 0;
}

/*
 * Decode the next valid UCS character from a UTF-8 string, skipping past bad
 * codes. Returns the decoded character or 0 for end-of-string and updates
 * nextc to point to the start of the next character (if any).
 * had_error is set if an invalid code was encountered.
 */
static u_int32_t
decode_utf8(const char *in, const char **nextc, int *had_error)
{
	int state = 0;
	size_t i;
	u_int32_t c, e;

	e = c = 0;
	for (i = 0; in[i] != '\0'; i++) {
		e = (u_char)in[i];
		/* Invalid code point state */
		if (state == -1) {
			/*
			 * Continue eating continuation characters until
			 * a new start character comes along.
			 */
			if ((e & 0xc0) == 0x80)
				continue;
			state = 0;
		}

		/* New code point state */
		if (state == 0) {
			if ((e & 0x80) == 0) { /* 7 bit code */
				c = e & 0x7f;
				goto have_code;
			} else if ((e & 0xe0) == 0xc0) { /* 11 bit code point */
				state = 1;
				c = (e & 0x1f) << 6;
			} else if ((e & 0xf0) == 0xe0) { /* 16 bit code point */
				state = 2;
				c = (e & 0xf) << 12;
			} else if ((e & 0xf8) == 0xf0) { /* 21 bit code point */
				state = 3;
				c = (e & 0x7) << 18;
			} else {
				/* A five or six byte header, or 0xff */
				goto bad_encoding;
			}
			/*
			 * Check that the header byte has some non-zero data
			 * after masking off the length marker. If not it is
			 * an invalid encoding.
			 */
			if (c == 0) {
 bad_encoding:
				c = 0;
				state = -1;
				if (had_error != NULL)
					*had_error = 1;
			}
			continue;
		}

		/* Sanity check: should never happen */
		if (state < 1 || state > 5) {
			*nextc = NULL;
			if (had_error != NULL)
				*had_error = 1;
			return 0;
		}
		/* Multibyte code point state */
		state--;
		c |= (e & 0x3f) << (state * 6);	
		if (state > 0)
			continue;

		/* RFC3629 bans codepoints > U+10FFFF */
		if (c > 0x10FFFF) {
			if (had_error != NULL)
				*had_error = 1;
			continue;
		}
 have_code:
		*nextc = in + i + 1;
		return c;
	}
	if (state != 0 && had_error != NULL)
		*had_error = 1;
	*nextc = in + i;
	return 0;
}

/*
 * Attempt to encode a UCS character as a UTF-8 sequence. Returns the number
 * of characters used or -1 on error (insufficient space or bad code).
 */
static int
encode_utf8(u_int32_t c, char *s, size_t slen)
{
	size_t i, need;
	u_char h;

	if (c < 0x80) {
		if (slen >= 1) {
			s[0] = (char)c;
		}
		return 1;
	} else if (c < 0x800) {
		need = 2;
		h = 0xc0;
	} else if (c < 0x10000) {
		need = 3;
		h = 0xe0;
	} else if (c < 0x200000) {
		need = 4;
		h = 0xf0;
	} else {
		/* Invalid code point > U+10FFFF */
		return -1;
	}
	if (need > slen)
		return -1;
	for (i = 0; i < need; i++) {
		s[i] = (i == 0 ? h : 0x80);
		s[i] |= (c >> (need - i - 1) * 6) & 0x3f;
	}
	return need;
}


/*
 * Normalise a UTF-8 string using the RFC3454 stringprep algorithm.
 * Returns 0 on success or -1 on failure (prohibited code or insufficient
 * length in the output string.
 * Requires an output buffer at most the same length as the input.
 */
int
utf8_stringprep(const char *in, char *out, size_t olen)
{
	int r;
	size_t o;
	u_int32_t c;

	if (olen < 1)
		return -1;

	for (o = 0; (c = decode_utf8(in, &in, NULL)) != 0;) {
		/* Mapping */
		if (code_in_table(c, map_to_nothing, sizeof(map_to_nothing)))
			continue;

		/* Prohibitied output */
		if (code_in_table(c, prohibited, sizeof(prohibited)) &&
		    !code_in_table(c, whitelist, sizeof(whitelist)))
			return -1;

		/* Map unassigned code points to U+FFFD */
		if (code_in_table(c, unassigned, sizeof(unassigned)))
			c = 0xFFFD;

		/* Encode the character */
		r = encode_utf8(c, out + o, olen - o - 1);
		if (r < 0)
			return -1;
		o += r;
	}
	out[o] = '\0';
	return 0;
}

