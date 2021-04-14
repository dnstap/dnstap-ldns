/*
 * Copyright (c) 2014-2015 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fstrm.h>
#include <ldns/ldns.h>

#include "dnstap.pb/dnstap.pb-c.h"

/* From our host2str.c. */
ldns_status my_ldns_pktheader2buffer_str(ldns_buffer *, const ldns_pkt *);
ldns_status my_ldns_pkt2buffer_str_fmt(ldns_buffer *, const ldns_output_format *, const ldns_pkt *);

static const char g_dnstap_content_type[] = "protobuf:dnstap.Dnstap";

typedef enum {
	dnstap_input_format_frame_stream = 0,
	dnstap_input_format_hex = 1,
} dnstap_input_format;

typedef enum {
	dnstap_output_format_yaml = 0,
	dnstap_output_format_quiet = 1,
} dnstap_output_format;

static void
print_string(const void *data, size_t len, FILE *out)
{
	uint8_t *str = (uint8_t *) data;
	fputc('"', out);
	while (len-- != 0) {
		unsigned c = *(str++);
		if (isprint(c)) {
			if (c == '"')
				fputs("\\\"", out);
			else
				fputc(c, out);
		} else {
			fprintf(out, "\\x%02x", c);
		}
	}
	fputc('"', out);
}

static bool
print_dns_question(const ProtobufCBinaryData *message, FILE *fp)
{
	char *str = NULL;
	ldns_pkt *pkt = NULL;
	ldns_rr *rr = NULL;
	ldns_rdf *qname = NULL;
	ldns_rr_class qclass = 0;
	ldns_rr_type qtype = 0;
	ldns_status status;

	/* Parse the raw wire message. */
	status = ldns_wire2pkt(&pkt, message->data, message->len);
	if (status == LDNS_STATUS_OK) {
		/* Get the question RR. */
		rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);

		/* Get the question name, class, and type. */
		if (rr) {
			qname = ldns_rr_owner(rr);
			qclass = ldns_rr_get_class(rr);
			qtype = ldns_rr_get_type(rr);
		}
	}

	if (status == LDNS_STATUS_OK && rr && qname) {
		/* Print the question name. */
		fputc('"', fp);
		ldns_rdf_print(fp, qname);
		fputc('"', fp);

		/* Print the question class. */
		str = ldns_rr_class2str(qclass);
		fputc(' ', fp);
		fputs(str, fp);
		free(str);

		/* Print the question type. */
		str = ldns_rr_type2str(qtype);
		fputc(' ', fp);
		fputs(str, fp);
		free(str);
	} else {
		fputs("? ? ?", fp);
	}

	/* Cleanup. */
	if (pkt != NULL)
		ldns_pkt_free(pkt);

	/* Success. */
	return true;
}

static bool
print_dns_message(const ProtobufCBinaryData *message, const char *field_name, FILE *fp)
{
	char *str = NULL;
	ldns_buffer *buf = NULL;
	ldns_pkt *pkt = NULL;
	ldns_status status;

	/* Initialize 'buf'. */
	buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!buf)
		return false;

	/* Parse the raw wire message. */
	status = ldns_wire2pkt(&pkt, message->data, message->len);
	if (status == LDNS_STATUS_OK) {
		/* Print the message, indented with spaces. */
		fprintf(fp, "  %s: |\n", field_name);

		status = my_ldns_pkt2buffer_str_fmt(buf, ldns_output_format_default, pkt);
		if (status == LDNS_STATUS_OK) {
			str = ldns_buffer_export2str(buf);
			fputs(str, fp);
		}
	} else {
		/* Parse failure. */
		fprintf(fp, "  # %s: parse failed\n", field_name);
	}

	/* Cleanup. */
	free(str);
	if (pkt != NULL)
		ldns_pkt_free(pkt);
	if (buf != NULL)
		ldns_buffer_free(buf);

	/* Success. */
	return true;
}

static bool
print_domain_name(const ProtobufCBinaryData *domain, FILE *fp)
{
	/* Wrap the binary data in 'domain' into an 'ldns_rdf'. */
	ldns_rdf *dname;
	assert(domain->data != NULL);
	dname = ldns_dname_new(domain->len, domain->data);
	if (!dname)
		return false;

	/* Print the presentation form of the domain name. */
	fputc('"', fp);
	ldns_rdf_print(fp, dname);
	fputc('"', fp);

	/* Success. */
	ldns_rdf_free(dname);
	return true;
}

static bool
print_ip_address(const ProtobufCBinaryData *ip, FILE *fp)
{
	char buf[INET6_ADDRSTRLEN] = {0};

	if (ip->len == 4) {
		/* Convert IPv4 address. */
		if (!inet_ntop(AF_INET, ip->data, buf, sizeof(buf)))
		    return false;
	} else if (ip->len == 16) {
		/* Convert IPv6 address. */
		if (!inet_ntop(AF_INET6, ip->data, buf, sizeof(buf)))
		    return false;
	} else {
		/* Unknown address family. */
		return false;
	}

	/* Print the presentation form of the IP address. */
	fputs(buf, fp);

	/* Success. */
	return true;
}

static bool
print_timestamp(uint64_t timestamp_sec, uint32_t timestamp_nsec, FILE *fp)
{
	static const char *fmt = "%F %H:%M:%S";

	char buf[100] = {0};
	struct tm tm;
	time_t t = (time_t) timestamp_sec;

	/* Convert arguments to broken-down 'struct tm'. */
	if (!gmtime_r(&t, &tm))
		return false;

	/* Format 'tm' into 'buf'. */
	if (strftime(buf, sizeof(buf), fmt, &tm) <= 0)
		return false;

	/* Print the timestamp. */
	fputs(buf, fp);
	fprintf(fp, ".%06u", timestamp_nsec / 1000);

	/* Success. */
	return true;
}

static bool
print_dnstap_message_quiet(const Dnstap__Message *m, FILE *fp)
{
	bool is_query = false;
	bool print_query_address = false;

	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
		is_query = true;
		break;
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		is_query = false;
		break;
	default:
		fputs("[unhandled Dnstap.Message.Type]\n", fp);
		return true;
	}

	/* Print timestamp. */
	if (is_query) {
		if (m->has_query_time_sec && m->has_query_time_nsec)
			print_timestamp(m->query_time_sec, m->query_time_nsec, fp);
		else
			fputs("??:??:??.??????", fp);
	} else {
		if (m->has_response_time_sec && m->has_response_time_nsec)
			print_timestamp(m->response_time_sec, m->response_time_nsec, fp);
		else
			fputs("??:??:??.??????", fp);
	}
	fputc(' ', fp);

	/* Print message type mnemonic. */
	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
		fputc('A', fp);
		break;
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
		fputc('C', fp);
		break;
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
		fputc('F', fp);
		break;
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
		fputc('R', fp);
		break;
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
		fputc('S', fp);
		break;
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		fputc('T', fp);
		break;
	default:
		fputc('?', fp);
		break;
	}
	if (is_query)
		fputs("Q ", fp);
	else
		fputs("R ", fp);

	/* Print query address or response address. */
	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
		print_query_address = true;
		break;
	default:
		print_query_address = false;
		break;
	}
	if (print_query_address) {
		if (m->has_query_address)
			print_ip_address(&m->query_address, fp);
		else
			fputs("MISSING_ADDRESS", fp);
	} else {
		if (m->has_response_address)
			print_ip_address(&m->response_address, fp);
		else
			fputs("MISSING_ADDRESS", fp);
	}
	fputc(' ', fp);

	/* Print socket protocol. */
	if (m->has_socket_protocol) {
		const ProtobufCEnumValue *type =
			protobuf_c_enum_descriptor_get_value(
				&dnstap__socket_protocol__descriptor,
				m->socket_protocol);
		if (type)
			fputs(type->name, fp);
		else
			fputs("?", fp);
	} else {
		fputs("?", fp);
	}
	fputc(' ', fp);

	/* Print message size. */
	if (is_query && m->has_query_message) {
		fprintf(fp, "%zdb ", m->query_message.len);
	} else if (!is_query && m->has_response_message) {
		fprintf(fp, "%zdb ", m->response_message.len);
	} else {
		fprintf(fp, "0b ");
	}

	/* Print question. */
	if (is_query && m->has_query_message) {
		if (!print_dns_question(&m->query_message, fp))
			return false;
	} else if (!is_query && m->has_response_message) {
		if (!print_dns_question(&m->response_message, fp))
			return false;
	} else {
		fputs("? ? ?", fp);
	}

	fputc('\n', fp);

	/* Success. */
	return true;
}

static bool
print_dnstap_message_yaml(const Dnstap__Message *m, FILE *fp)
{
	/* Print 'type' field. */
	const ProtobufCEnumValue *m_type =
		protobuf_c_enum_descriptor_get_value(
			&dnstap__message__type__descriptor,
			m->type);
	if (!m_type)
		return false;
	fputs("  type: ", fp);
	fputs(m_type->name, fp);
	fputc('\n', fp);

	/* Print 'query_time' field. */
	if (m->has_query_time_sec && m->has_query_time_nsec) {
		fputs("  query_time: !!timestamp ", fp);
		print_timestamp(m->query_time_sec, m->query_time_nsec, fp);
		fputc('\n', fp);
	}

	/* Print 'response_time' field. */
	if (m->has_response_time_sec && m->has_response_time_nsec) {
		fputs("  response_time: !!timestamp ", fp);
		print_timestamp(m->response_time_sec, m->response_time_nsec, fp);
		fputc('\n', fp);
	}

	/* Print 'socket_family' field. */
	if (m->has_socket_family) {
		const ProtobufCEnumValue *type =
			protobuf_c_enum_descriptor_get_value(
				&dnstap__socket_family__descriptor,
				m->socket_family);
		if (!type)
			return false;
		fputs("  socket_family: ", fp);
		fputs(type->name, fp);
		fputc('\n', fp);
	}

	/* Print 'socket_protocol' field. */
	if (m->has_socket_protocol) {
		const ProtobufCEnumValue *type =
			protobuf_c_enum_descriptor_get_value(
				&dnstap__socket_protocol__descriptor,
				m->socket_protocol);
		if (!type)
			return false;
		fputs("  socket_protocol: ", fp);
		fputs(type->name, fp);
		fputc('\n', fp);
	}

	/* Print 'query_address' field. */
	if (m->has_query_address) {
		fputs("  query_address: ", fp);
		print_ip_address(&m->query_address, fp);
		fputc('\n', fp);
	}

	/* Print 'response_address field. */
	if (m->has_response_address) {
		fputs("  response_address: ", fp);
		print_ip_address(&m->response_address, fp);
		fputc('\n', fp);
	}

	/* Print 'query_port' field. */
	if (m->has_query_port)
		fprintf(fp, "  query_port: %u\n", m->query_port);

	/* Print 'response_port' field. */
	if (m->has_response_port)
		fprintf(fp, "  response_port: %u\n", m->response_port);

	/* Print 'query_zone' field. */
	if (m->has_query_zone && m->query_zone.data != NULL) {
		fputs("  query_zone: ", fp);
		print_domain_name(&m->query_zone, fp);
		fputc('\n', fp);
	}

	/* Print 'query_message' field. */
	if (m->has_query_message) {
		if (!print_dns_message(&m->query_message, "query_message", fp))
			return false;
	}

	/* Print 'response_message' field .*/
	if (m->has_response_message) {
		if (!print_dns_message(&m->response_message, "response_message", fp))
			return false;
	}

	/* Success. */
	fputs("---\n", fp);
	return true;
}

static bool
print_dnstap_frame_quiet(const Dnstap__Dnstap *d, FILE *fp)
{
	if (d->type == DNSTAP__DNSTAP__TYPE__MESSAGE && d->message != NULL) {
		return print_dnstap_message_quiet(d->message, fp);
	} else {
		fputs("[unhandled Dnstap.Type]\n", fp);
	}

	/* Success. */
	return true;
}

static bool
print_dnstap_frame_yaml(const Dnstap__Dnstap *d, FILE *fp)
{
	/* Print 'type' field. */
	const ProtobufCEnumValue *d_type =
		protobuf_c_enum_descriptor_get_value(
			&dnstap__dnstap__type__descriptor,
			d->type);
	if (!d_type)
		return false;
	fputs("type: ", fp);
	fputs(d_type->name, fp);
	fputc('\n', fp);

	/* Print 'identity' field. */
	if (d->has_identity) {
		fputs("identity: ", fp);
		print_string(d->identity.data, d->identity.len, fp);
		fputc('\n', fp);
	}

	/* Print 'version' field. */
	if (d->has_version) {
		fputs("version: ", fp);
		print_string(d->version.data, d->version.len, fp);
		fputc('\n', fp);
	}

	/* Print 'message' field. */
	if (d->type == DNSTAP__DNSTAP__TYPE__MESSAGE && d->message != NULL) {
		fputs("message:\n", fp);
		if (!print_dnstap_message_yaml(d->message, fp))
			return false;
	}

	/* Success. */
	return true;
}

static bool
print_dnstap_frame(const uint8_t *data, size_t len_data, dnstap_output_format fmt, FILE *fp)
{
	bool rv = false;
	Dnstap__Dnstap *d = NULL;

	//fprintf(stderr, "%s: len = %zd\n", __func__, len_data);

	/* Unpack the data frame. */
	d = dnstap__dnstap__unpack(NULL, len_data, data);
	if (!d) {
		fprintf(stderr, "%s: dnstap__dnstap__unpack() failed.\n", __func__);
		goto out;
	}

	if (fmt == dnstap_output_format_yaml) {
		if (!print_dnstap_frame_yaml(d, fp))
			goto out;
	} else if (fmt == dnstap_output_format_quiet) {
		if (!print_dnstap_frame_quiet(d, fp))
			goto out;
	} else {
		fprintf(stderr, "%s: unknown output format %d\n", __func__, fmt);
		goto out;
	}

	/* Success. */
	rv = true;

out:
	/* Cleanup protobuf-c allocations. */
	if (d)
		dnstap__dnstap__free_unpacked(d, NULL);

	/* Success. */
	return rv;
}

static bool
verify_content_type(struct fstrm_reader *r, const uint8_t *content_type,
		    size_t len_content_type)
{
	fstrm_res res;
	const struct fstrm_control *control = NULL;
	size_t n_content_type = 0;
	const uint8_t *r_content_type = NULL;
	size_t len_r_content_type = 0;

	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &control);
	if (res != fstrm_res_success)
		return false;

	res = fstrm_control_get_num_field_content_type(control, &n_content_type);
	if (res != fstrm_res_success)
		return false;
	if (n_content_type > 0) {
		res = fstrm_control_get_field_content_type(control, 0,
			&r_content_type, &len_r_content_type);
		if (res != fstrm_res_success)
			return false;

		if (len_content_type != len_r_content_type)
			return false;

		if (memcmp(content_type, r_content_type, len_content_type) == 0)
			return true;
	}

	return false;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: dnstap-ldns [OPTION]...\n");
	fprintf(stderr, "  -q        Use quiet text output format\n");
	fprintf(stderr, "  -y        Use verbose YAML output format\n");
	fprintf(stderr, "  -x        Input format is hexlified protobuf or NULL RR\n");
	fprintf(stderr, "  -r <FILE> Read dnstap payloads from file\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Quiet text output format mnemonics:\n");
	fprintf(stderr, "  AQ: AUTH_QUERY\n");
	fprintf(stderr, "  AR: AUTH_RESPONSE\n");
	fprintf(stderr, "  RQ: RESOLVER_QUERY\n");
	fprintf(stderr, "  RR: RESOLVER_RESPONSE\n");
	fprintf(stderr, "  CQ: CLIENT_QUERY\n");
	fprintf(stderr, "  CR: CLIENT_RESPONSE\n");
	fprintf(stderr, "  FQ: FORWARDER_QUERY\n");
	fprintf(stderr, "  FR: FORWARDER_RESPONSE\n");
	fprintf(stderr, "  SQ: STUB_QUERY\n");
	fprintf(stderr, "  SR: STUB_RESPONSE\n");
	fprintf(stderr, "  TQ: TOOL_QUERY\n");
	fprintf(stderr, "  TR: TOOL_RESPONSE\n");
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static int
read_input_frame_stream(const char *input_fname,
			const dnstap_output_format fmt)
{
	struct fstrm_reader *r = NULL;
	int rv = EXIT_FAILURE;
	fstrm_res res;

	if (input_fname) {
		/* Setup file reader options. */
		struct fstrm_file_options *fopt;
		fopt = fstrm_file_options_init();
		fstrm_file_options_set_file_path(fopt, input_fname);

		/* Initialize file reader. */
		r = fstrm_file_reader_init(fopt, NULL);
		if (!r) {
			fputs("Error: fstrm_file_reader_init() failed.\n", stderr);
			goto out;
		}
		res = fstrm_reader_open(r);
		if (res != fstrm_res_success) {
			fputs("Error: fstrm_reader_option() failed.\n", stderr);
			goto out;
		}

		/* Cleanup. */
		fstrm_file_options_destroy(&fopt);

		/* Verify "Content Type" field. */
		if (!verify_content_type(r, (const uint8_t *) g_dnstap_content_type,
					 strlen(g_dnstap_content_type)))
		{
			fprintf(stderr, "Error: %s is not a dnstap file.\n", input_fname);
			goto out;
		}
	} else {
		fprintf(stderr, "Error: no input specified, try -r <FILE>.\n\n");
		usage();
	}

	/* Loop over data frames. */
	for (;;) {
		const uint8_t *data;
		size_t len_data;

		res = fstrm_reader_read(r, &data, &len_data);
		if (res == fstrm_res_success) {
			/* Data frame ready. */
			if (!print_dnstap_frame(data, len_data, fmt, stdout)) {
				fputs("Error: print_dnstap_frame() failed.\n", stderr);
				goto out;
			}
		} else if (res == fstrm_res_stop) {
			/* Normal end of data stream. */
			rv = EXIT_SUCCESS;
			goto out;
		} else {
			/* Abnormal end. */
			fputs("Error: fstrm_reader_read() failed.\n", stderr);
			goto out;
		}
	}

out:
	/* Cleanup. */
	fstrm_reader_destroy(&r);

	return rv;
}

static int
read_input_hex(const char *input_fname,
	       const dnstap_output_format fmt)
{
	int rv = EXIT_FAILURE;
	FILE *r = NULL;
	ldns_rdf *rdf = NULL;
	ldns_rr *rr = NULL;

	/* Allocate buffer for input data. */
	static const size_t alloc_bytes = 262144;
	uint8_t *data = calloc(1, alloc_bytes);
	assert(data != NULL);

	/* Open the input file stream. */
	if (!input_fname || strcmp(input_fname, "-") == 0) {
		r = stdin;
	} else {
		r = fopen(input_fname, "r");
		if (!r) {
			fputs("Error: fopen() failed.\n", stderr);
			goto out;
		}
	}

	/* Read up to 'alloc_bytes' from input stream. */
	const size_t len_data = fread(data, 1, alloc_bytes, r);
	if (ferror(r)) {
		fputs("Error: fread() failed.\n", stderr);
		goto out;
	}
	if (!feof(r)) {
		fputs("Error: Too much data from input.\n", stderr);
		goto out;
	}

	/* If present, trim \# and data length, for RFC 3597 rdata. */
	char *p = data;
	if (len_data >= 4 &&
	    p[0] == '\\' &&
	    p[1] == '#' &&
	    p[2] == ' ')
	{
		/* Trim the "\# ". */
		p += 3;

		/* Trim the rdata length. */
		p = strchr(p, ' ');
		if (!p)
			goto out;
	}

	/* Unhexlify the data. */
	ldns_status status = ldns_str2rdf_hex(&rdf, p);
	if (status != LDNS_STATUS_OK) {
		/**
		 * Failed to parse as hex or 3597 rdata, try to parse as a
		 * master format NULL RR, possibly in multi-line format with
		 * comments (e.g., dig output).
		 */
		char *line = NULL;
		char *saveptr = NULL;

		line = strtok_r(data, "\n\r", &saveptr);
		if (!line)
			goto out;

		do {
			status = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
			if (status == LDNS_STATUS_OK)
				break;
			line = strtok_r(NULL, "\n\r", &saveptr);
		} while (line);

		if (!rr) {
			fprintf(stderr, "Error: Unable to decode as hex or RR. Bad input?\n");
			goto out;
		}

		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_NULL) {
			fprintf(stderr, "Error: Unexpected rrtype (%u).\n",
				ldns_rr_get_type(rr));
			goto out;
		}

		if (ldns_rr_rd_count(rr) != 1) {
			fprintf(stderr, "Error: Unexpected rdf count (%zu).\n",
				ldns_rr_rd_count(rr));
			goto out;
		}

		rdf = ldns_rr_pop_rdf(rr);
	}

	/* Get the raw data pointer out of the wrapped ldns type. */
	uint8_t *raw = ldns_rdf_data(rdf);
	size_t len_raw = ldns_rdf_size(rdf);

	/* Decode and print the protobuf message. */
	if (!print_dnstap_frame(raw, len_raw, fmt, stdout)) {
		fputs("Error: print_dnstap_frame() failed.\n", stderr);
		goto out;
	}

	/* Success. */
	rv = EXIT_SUCCESS;

out:
	/* Cleanup. */
	if (r)
		fclose(r);
	if (rdf)
		ldns_rdf_deep_free(rdf);
	if (rr)
		ldns_rr_free(rr);
	free(data);

	return rv;
}

int
main(int argc, char **argv)
{
	int c;
	int rv = EXIT_FAILURE;
	const char *input_fname = NULL;
	dnstap_input_format in_fmt = dnstap_input_format_frame_stream;
	dnstap_output_format out_fmt = dnstap_output_format_quiet;

	/* Args. */
	while ((c = getopt(argc, argv, "qyxr:")) != -1) {
		switch (c) {
		case 'q':
			out_fmt = dnstap_output_format_quiet;
			break;
		case 'y':
			out_fmt = dnstap_output_format_yaml;
			break;
		case 'x':
			in_fmt = dnstap_input_format_hex;
			break;
		case 'r':
			input_fname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	if (in_fmt == dnstap_input_format_frame_stream) {
		rv = read_input_frame_stream(input_fname, out_fmt);
	} else if (in_fmt == dnstap_input_format_hex) {
		rv = read_input_hex(input_fname, out_fmt);
	} else {
		rv = EXIT_FAILURE;
	}

	return rv;
}
