/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/aspa/aspa.h"
#include "rtrlib/aspa/aspa_array/aspa_array.h"
#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/lib/convert_byte_order_private.h"
#include "rtrlib/rtr/packets_private.h"
#include "rtrlib/rtr/rtr_pdus.h"
#include "rtrlib/transport/transport.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

char *data;
size_t data_size = 0;
size_t data_index = 0;

#define c16(X) lrtr_convert_short(TO_HOST_HOST_BYTE_ORDER, X)
#define c32(X) lrtr_convert_long(TO_HOST_HOST_BYTE_ORDER, X)

static int custom_send(const struct tr_socket *socket, const void *pdu, const size_t len, const time_t timeout)
{
	printf("sent %lu bytes\n", len);

	const struct pdu_error *err = pdu;
	if (err->type == 10) {
		uint32_t *errlen = (uint32_t *)((char *)err->rest + err->len_enc_pdu);
		if ((char *)errlen < (char *)err + c32(err->len)) {
			printf("err msg: %.*s\n", *errlen, (char *)(errlen + 1));
		}
	}
	return len;
}

static int custom_recv(const struct tr_socket *socket, const void *buf, const size_t len, const time_t timeout)
{
	size_t rlen = len;
	if (data_index + rlen > data_size)
		rlen = data_size - data_index;

	memcpy((char *)buf, data + data_index, rlen);
	data_index += rlen;
	printf("read %lu bytes\n", rlen);
	return rlen;
}

static void begin_cache_response(uint8_t version, uint16_t session_id)
{
	if (data) {
		lrtr_free(data);
		data = NULL;
		data_size = 0;
		data_index = 0;
	}

	data = lrtr_malloc(sizeof(struct pdu_cache_response));
	assert(data);

	struct pdu_cache_response *cache_response = (struct pdu_cache_response *)data;
	cache_response->ver = version;
	cache_response->type = CACHE_RESPONSE;
	cache_response->session_id = c16(session_id);
	cache_response->len = c32(8);

	data_size += sizeof(struct pdu_cache_response);
}

static void append_aspa(uint8_t version, uint8_t flags, uint32_t customer_asn, uint32_t provider_asns[],
			size_t provider_count)
{
	size_t pdu_size = sizeof(struct pdu_aspa) + sizeof(uint32_t) * provider_count;

	data = lrtr_realloc(data, data_size + pdu_size);
	assert(data);

	struct pdu_aspa *aspa = (struct pdu_aspa *)(data + data_size);
	aspa->ver = version;
	aspa->type = ASPA;
	aspa->zero = 0;
	aspa->len = c32(pdu_size);
	aspa->flags = flags;
	aspa->afi_flags = 0x3;
	aspa->provider_count = c16((uint16_t)provider_count);
	aspa->customer_asn = c32(customer_asn);

	for (size_t i = 0; i < provider_count; i++) {
		provider_asns[i] = c32(provider_asns[i]);
	}

	memcpy(aspa->provider_asns, provider_asns, sizeof(uint32_t) * provider_count);
	data_size += pdu_size;
}

static void end_cache_response(uint8_t version, uint16_t session_id, uint32_t sn)
{
	data = lrtr_realloc(data, data_size + sizeof(struct pdu_end_of_data_v1_v2));
	assert(data);

	struct pdu_end_of_data_v1_v2 *eod = (struct pdu_end_of_data_v1_v2 *)(data + data_size);
	eod->ver = version;
	eod->type = EOD;
	eod->session_id = c16(session_id);
	eod->len = c32(24);
	eod->sn = c32(sn);
	eod->refresh_interval = 0;
	eod->retry_interval = 0;
	eod->expire_interval = 0;

	data_size += sizeof(struct pdu_end_of_data_v1_v2);
}

static void test_table(struct rtr_socket *socket, struct aspa_record records[], size_t record_count)
{
	assert(socket->aspa_table);
	assert(socket->aspa_table->store);
	assert(socket->aspa_table->store->aspa_array);
	assert(socket->aspa_table->store->rtr_socket);
	assert(socket->aspa_table->store->rtr_socket == socket);
	assert(socket->aspa_table->store->next == NULL);

	struct aspa_array *array = socket->aspa_table->store->aspa_array;
	assert(array->size == record_count);

	if (record_count <= 0)
		return;

	assert(records);
	assert(array->data);

	for (size_t i = 0; i < record_count; i++) {
		assert(array->data[i].customer_asn == records[i].customer_asn);
		assert(array->data[i].provider_count == records[i].provider_count);

		for (size_t k = 0; k < records[i].provider_count; k++) {
			assert(array->data[i].provider_asns[k] == records[i].provider_asns[k]);
		}
	}
}

static void test_sync(struct rtr_socket *socket)
{
	// Test: regular announcement
	// Expect: OK
	// DB: inserted
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, 1, 1100, (uint32_t[]){1101, 1102, 1103, 1104}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
	printf("TEST: regular announcement: as expected\n\n");

	// Test: Announce existing record
	// Expect: ERROR
	// DB: no change
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, 1, 1100, (uint32_t[]){201, 2202, 2203, 2204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
	printf("TEST: announce existing: as expected\n\n");

	// Test: Announce new record twice (duplicate)
	// Expect: ERROR
	// DB: no change

	// Test: Withdraw non-existant record
	// Expect: ERROR
	// DB: no change

	// Test: Announce record, immediately withdraw within same sync op
	// Expect: OK
	// DB: no change

	// Test: Withdraw existing record, immediately announce record with same ASN within same sync op
	// Expect: OK
	// DB: record gets replaced
    
    // Test: regular announcements and withdrawals
    // Expect: OK
    // DB: records get removed, newly announced are added
}

int main()
{
	struct tr_socket *tr_socket = lrtr_malloc(sizeof(struct tr_socket));
	tr_socket->recv_fp = (tr_recv_fp)&custom_recv;
	tr_socket->send_fp = (tr_send_fp)&custom_send;

	struct rtr_socket *socket = lrtr_malloc(sizeof(struct rtr_socket));
	assert(socket);
	socket->version = 2;
	socket->state = RTR_SYNC;
	socket->tr_socket = tr_socket;

	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table);
	aspa_table_init(aspa_table, NULL);
	socket->aspa_table = aspa_table;

	test_sync(socket);

	if (data) {
		lrtr_free(data);
		data = NULL;
		data_size = 0;
		data_index = 0;
	}
	return 0;
}
