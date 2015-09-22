/*
 * Copyright (c) 2005,2006, NLnetLabs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of NLnetLabs nor the names of its
 *       contributors may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ldns/ldns.h>

/* Adapted from ldns_pktheader2buffer_str() from ldns host2str.c. */
ldns_status
my_ldns_pktheader2buffer_str(ldns_buffer *output, const ldns_pkt *pkt)
{
	ldns_lookup_table *opcode = ldns_lookup_by_id(ldns_opcodes,
			                    (int) ldns_pkt_get_opcode(pkt));
	ldns_lookup_table *rcode = ldns_lookup_by_id(ldns_rcodes,
			                    (int) ldns_pkt_get_rcode(pkt));

	ldns_buffer_printf(output, "    ");
	ldns_buffer_printf(output, ";; ->>HEADER<<- ");
	if (opcode) {
		ldns_buffer_printf(output, "opcode: %s, ", opcode->name);
	} else {
		ldns_buffer_printf(output, "opcode: ?? (%u), ",
				ldns_pkt_get_opcode(pkt));
	}
	if (rcode) {
		ldns_buffer_printf(output, "rcode: %s, ", rcode->name);
	} else {
		ldns_buffer_printf(output, "rcode: ?? (%u), ", ldns_pkt_get_rcode(pkt));
	}
	ldns_buffer_printf(output, "id: %d\n", ldns_pkt_id(pkt));
	ldns_buffer_printf(output, "    ");
	ldns_buffer_printf(output, ";; flags: ");

	if (ldns_pkt_qr(pkt)) {
		ldns_buffer_printf(output, "qr ");
	}
	if (ldns_pkt_aa(pkt)) {
		ldns_buffer_printf(output, "aa ");
	}
	if (ldns_pkt_tc(pkt)) {
		ldns_buffer_printf(output, "tc ");
	}
	if (ldns_pkt_rd(pkt)) {
		ldns_buffer_printf(output, "rd ");
	}
	if (ldns_pkt_cd(pkt)) {
		ldns_buffer_printf(output, "cd ");
	}
	if (ldns_pkt_ra(pkt)) {
		ldns_buffer_printf(output, "ra ");
	}
	if (ldns_pkt_ad(pkt)) {
		ldns_buffer_printf(output, "ad ");
	}
	ldns_buffer_printf(output, "; ");
	ldns_buffer_printf(output, "QUERY: %u, ", ldns_pkt_qdcount(pkt));
	ldns_buffer_printf(output, "ANSWER: %u, ", ldns_pkt_ancount(pkt));
	ldns_buffer_printf(output, "AUTHORITY: %u, ", ldns_pkt_nscount(pkt));
	ldns_buffer_printf(output, "ADDITIONAL: %u ", ldns_pkt_arcount(pkt));
	return ldns_buffer_status(output);
}

/* Adapted from ldns_pkt2buffer_str_fmt() from ldns host2str.c. */
ldns_status
my_ldns_pkt2buffer_str_fmt(ldns_buffer *output,
			   const ldns_output_format *fmt,
			   const ldns_pkt *pkt)
{
	uint16_t i;
	ldns_status status = LDNS_STATUS_OK;

	if (!pkt) {
		ldns_buffer_printf(output, "null");
		return LDNS_STATUS_OK;
	}

	if (ldns_buffer_status_ok(output)) {
		status = my_ldns_pktheader2buffer_str(output, pkt);
		if (status != LDNS_STATUS_OK) {
			return status;
		}

		ldns_buffer_printf(output, "\n\n");

		ldns_buffer_printf(output, "    ;; QUESTION SECTION:\n    ;");

		for (i = 0; i < ldns_pkt_qdcount(pkt); i++) {
			status = ldns_rr2buffer_str_fmt(output, fmt,
				       ldns_rr_list_rr(
					       ldns_pkt_question(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}
		}
		ldns_buffer_printf(output, "\n");

		ldns_buffer_printf(output, "    ;; ANSWER SECTION:\n");
		for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
			ldns_buffer_printf(output, "    ");
			status = ldns_rr2buffer_str_fmt(output, fmt,
				       ldns_rr_list_rr(
					       ldns_pkt_answer(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

		}
		ldns_buffer_printf(output, "\n");

		ldns_buffer_printf(output, "    ;; AUTHORITY SECTION:\n");

		for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
			ldns_buffer_printf(output, "    ");
			status = ldns_rr2buffer_str_fmt(output, fmt,
				       ldns_rr_list_rr(
					       ldns_pkt_authority(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}
		}
		ldns_buffer_printf(output, "\n");

		ldns_buffer_printf(output, "    ;; ADDITIONAL SECTION:\n");
		for (i = 0; i < ldns_pkt_arcount(pkt); i++) {
			ldns_buffer_printf(output, "    ");
			status = ldns_rr2buffer_str_fmt(output, fmt,
				       ldns_rr_list_rr(
					       ldns_pkt_additional(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

		}
		ldns_buffer_printf(output, "\n");

		/* add some futher fields */
		if (ldns_pkt_edns(pkt)) {
			ldns_buffer_printf(output, "    ");
			ldns_buffer_printf(output,
				   ";; EDNS: version %u; flags:",
				   ldns_pkt_edns_version(pkt));
			if (ldns_pkt_edns_do(pkt)) {
				ldns_buffer_printf(output, " do");
			}
			/* the extended rcode is the value set, shifted four bits,
			 * and or'd with the original rcode */
			if (ldns_pkt_edns_extended_rcode(pkt)) {
				ldns_buffer_printf(output, " ; ext-rcode: %d",
					(ldns_pkt_edns_extended_rcode(pkt) << 4 | ldns_pkt_get_rcode(pkt)));
			}
			ldns_buffer_printf(output, " ; udp: %u\n",
					   ldns_pkt_edns_udp_size(pkt));

			if (ldns_pkt_edns_data(pkt)) {
				ldns_buffer_printf(output, "    ");
				ldns_buffer_printf(output, ";; Data: ");
				(void)ldns_rdf2buffer_str(output,
							  ldns_pkt_edns_data(pkt));
				ldns_buffer_printf(output, "\n");
			}
		}
		if (ldns_pkt_tsig(pkt)) {
			ldns_buffer_printf(output, "    ");
			ldns_buffer_printf(output, ";; TSIG:\n;; ");
			(void) ldns_rr2buffer_str_fmt(
					output, fmt, ldns_pkt_tsig(pkt));
			ldns_buffer_printf(output, "\n");
		}
	} else {
		return ldns_buffer_status(output);
	}
	return status;
}
