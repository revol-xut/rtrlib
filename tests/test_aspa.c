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

static struct pdu_cache_response *begin_cache_response(uint8_t version, uint16_t session_id)
{
	if (data == NULL)
		data = lrtr_malloc(sizeof(struct pdu_cache_response));
	else
		data = lrtr_realloc(data, data_size + sizeof(struct pdu_cache_response));

	assert(data);

	struct pdu_cache_response *cache_response = (struct pdu_cache_response *)(data + data_size);
	cache_response->ver = version;
	cache_response->type = CACHE_RESPONSE;
	cache_response->session_id = c16(session_id);
	cache_response->len = c32(8);

	data_size += sizeof(struct pdu_cache_response);

	return cache_response;
}

static uint8_t ASPA_ANNOUNCE = 1;
static uint8_t ASPA_WITHDRAW = 0;

static struct pdu_aspa *append_aspa(uint8_t version, uint8_t flags, uint32_t customer_asn, uint32_t provider_asns[],
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

	return aspa;
}

static struct pdu_end_of_data_v1_v2 *end_cache_response(uint8_t version, uint16_t session_id, uint32_t sn)
{
	data = lrtr_realloc(data, data_size + sizeof(struct pdu_end_of_data_v1_v2));
	assert(data);

	struct pdu_end_of_data_v1_v2 *eod = (struct pdu_end_of_data_v1_v2 *)(data + data_size);
	eod->ver = version;
	eod->type = EOD;
	eod->session_id = c16(session_id);
	eod->len = c32(24);
	eod->sn = c32(sn);
	eod->refresh_interval = c32(RTR_REFRESH_MIN);
	eod->retry_interval = c32(RTR_RETRY_MIN);
	eod->expire_interval = c32(RTR_EXPIRATION_MIN);

	data_size += sizeof(struct pdu_end_of_data_v1_v2);

	return eod;
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
	if(array->size != record_count)
		printf("error!");
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

static void test_regular_announcement(struct rtr_socket *socket)
{
	// Test: regular announcement
	// Expect: OK
	// DB: inserted
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){1101, 1102, 1103, 1104}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
}

static void test_announce_existing(struct rtr_socket *socket)
{
	// Test: Announce for existing customer_asn
	// Expect: ERROR
	// DB: no change

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){2201, 2202, 2203, 2204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
}

static void test_announce_twice(struct rtr_socket *socket)
{
	// Test: Announce new record again (duplicate)
	// Expect: ERROR
	// DB: no change

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){1101, 1102, 1103, 1104}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
}

static void test_withdraw_nonexisting(struct rtr_socket *socket)
{
	// Test: Withdraw non-existent record
	// Expect: ERROR
	// DB: no change

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 3300, (uint32_t[]){}, 0);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
}

static void test_announce_withdraw(struct rtr_socket *socket)
{
	// Test: Announce record, immediately withdraw within same sync op
	// Expect: OK
	// DB: no change

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, (uint32_t[]){3301, 3302, 3303, 3304}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 3300, (uint32_t[]){}, 0);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}}},
		   1);
}

static void test_withdraw_announce(struct rtr_socket *socket)
{
	// Test: Withdraw existing record, immediately announce record with same ASN within same sync op
	// Expect: OK
	// DB: record gets replaced

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){2201, 2202, 2203, 2204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){(struct aspa_record){.customer_asn = 1100,
							       .provider_count = 4,
							       .provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}}},
		   1);
}

static void test_regular(struct rtr_socket *socket)
{
	// Test: regular announcements and withdrawals
	// Expect: OK
	// DB: records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){1101, 1102, 1103, 1104}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1101, (uint32_t[]){1100, 1102, 1103, 1104}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 2200, (uint32_t[]){2201, 2202, 2203, 2204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1100,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}},
			   (struct aspa_record){.customer_asn = 1101,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1100, 1102, 1103, 1104}},
			   (struct aspa_record){.customer_asn = 2200,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}},
		   },
		   3);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, (uint32_t[]){3301, 3302, 3303, 3304}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1100,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1101, 1102, 1103, 1104}},
			   (struct aspa_record){.customer_asn = 1101,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1100, 1102, 1103, 1104}},
			   (struct aspa_record){.customer_asn = 2200,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}},
			   (struct aspa_record){.customer_asn = 3300,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		   },
		   4);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 2200, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, (uint32_t[]){1201, 1202, 1203, 1204}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 0, (uint32_t[]){}, 0);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	printf("coming up!\n");
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(
		socket,
		(struct aspa_record[]){
			(struct aspa_record){.customer_asn = 0, .provider_count = 0, .provider_asns = (uint32_t[]){}},
			(struct aspa_record){.customer_asn = 1100,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1201, 1202, 1203, 1204}},
			(struct aspa_record){.customer_asn = 1101,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1100, 1102, 1103, 1104}},
			(struct aspa_record){.customer_asn = 3300,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		},
		4);
}

static void test_withdraw_twice(struct rtr_socket *socket)
{
	// Test: duplicate in-sequence withdrawal
	// Expect: Error
	// DB: records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1900, (uint32_t[]){1901, 1902, 1903, 1904}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1901, (uint32_t[]){1900, 1902, 1903, 1904}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 2200, (uint32_t[]){2201, 2202, 2203, 2204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1900,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1901, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 1901,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1900, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 2200,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}},
		   },
		   3);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, (uint32_t[]){3301, 3302, 3303, 3304}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1900,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1901, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 1901,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1900, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 2200,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}},
			   (struct aspa_record){.customer_asn = 3300,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		   },
		   4);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1900, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 2200, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1900, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1900, (uint32_t[]){1201, 1202, 1203, 1204}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 0, (uint32_t[]){}, 0);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	printf("upcoming!\n");
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1900,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1901, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 1901,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1900, 1902, 1903, 1904}},
			   (struct aspa_record){.customer_asn = 2200,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){2201, 2202, 2203, 2204}},
			   (struct aspa_record){.customer_asn = 3300,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		   },
		   4);
}

static void test_announce_withdraw_announce_twice(struct rtr_socket *socket)
{
	// Test: regular announcements and withdrawals
	// Expect: OK
	// DB: records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, (uint32_t[]){1401, 1402, 1403, 1404}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);
	assert(rtr_sync(socket) == RTR_SUCCESS);
	test_table(socket,
		   (struct aspa_record[]){
			   (struct aspa_record){.customer_asn = 1400,
						.provider_count = 4,
						.provider_asns = (uint32_t[]){1401, 1402, 1403, 1404}},
		   },
		   1);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1400, (uint32_t[]){}, 0);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, (uint32_t[]){1201, 1202, 1203, 1204}, 4);
	append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, (uint32_t[]){1201, 1202, 1203, 1204}, 4);
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	/*
	test_table(
		socket,
		(struct aspa_record[]){
			(struct aspa_record){.customer_asn = 0, .provider_count = 0, .provider_asns = (uint32_t[]){}},
			(struct aspa_record){.customer_asn = 1100,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1201, 1202, 1203, 1204}},
			(struct aspa_record){.customer_asn = 1101,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1100, 1102, 1103, 1104}},
			(struct aspa_record){.customer_asn = 3300,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		},
		4);
		*/
}

static void test_corrupt(struct rtr_socket *socket)
{
	// Test: send corrupt pdu after having received valid data
	// Expect: Error
	// DB: DB stays the same

	test_regular(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	struct pdu_aspa *aspa =
		append_aspa(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 4400, (uint32_t[]){4401, 4402, 4403, 4404}, 4);

	// corrupt ASPA len
	aspa->len = c32(c32(aspa->len) + 1);

	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);
	assert(rtr_sync(socket) == RTR_ERROR);
	test_table(
		socket,
		(struct aspa_record[]){
			(struct aspa_record){.customer_asn = 0, .provider_count = 0, .provider_asns = (uint32_t[]){}},
			(struct aspa_record){.customer_asn = 1100,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1201, 1202, 1203, 1204}},
			(struct aspa_record){.customer_asn = 1101,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){1100, 1102, 1103, 1104}},
			(struct aspa_record){.customer_asn = 3300,
					     .provider_count = 4,
					     .provider_asns = (uint32_t[]){3301, 3302, 3303, 3304}},
		},
		4);
}

static void reset_data()
{
	printf("resetting...\n");
	if (data) {
		lrtr_free(data);
		data = NULL;
		data_size = 0;
		data_index = 0;
	}
}

static struct rtr_socket *fresh_socket()
{
	struct tr_socket *tr_socket = lrtr_calloc(1, sizeof(struct tr_socket));
	tr_socket->recv_fp = (tr_recv_fp)&custom_recv;
	tr_socket->send_fp = (tr_send_fp)&custom_send;

	struct rtr_socket *socket = lrtr_calloc(1, sizeof(struct rtr_socket));
	assert(socket);
	socket->version = 2;
	socket->state = RTR_SYNC;
	socket->tr_socket = tr_socket;

	struct aspa_table *aspa_table = lrtr_calloc(1, sizeof(*aspa_table));
	assert(aspa_table);
	aspa_table_init(aspa_table, NULL);
	socket->aspa_table = aspa_table;

	return socket;
}

int main()
{
	reset_data();
	printf("\n\ntest_regular_announcement\n\n");
	test_regular_announcement(fresh_socket());

	reset_data();
	printf("\n\ntest_regular_announcement\n\n");
	test_regular_announcement(fresh_socket());

	reset_data();
	printf("\n\ntest_announce_existing\n\n");
	test_announce_existing(fresh_socket());

	reset_data();
	printf("\n\ntest_announce_twice\n\n");
	test_announce_twice(fresh_socket());

	reset_data();
	printf("\n\ntest_withdraw_nonexisting\n\n");
	test_withdraw_nonexisting(fresh_socket());

	reset_data();
	printf("\n\ntest_announce_withdraw\n\n");
	test_announce_withdraw(fresh_socket());

	reset_data();
	printf("\n\ntest_withdraw_announce\n\n");
	test_withdraw_announce(fresh_socket());

	reset_data();
	printf("\n\ntest_regular\n\n");
	test_regular(fresh_socket());

	reset_data();
	printf("\n\ntest_withdraw_twice\n\n");
	test_withdraw_twice(fresh_socket());

	reset_data();
	printf("\n\ntest_corrupt\n\n");
	test_corrupt(fresh_socket());

	reset_data();
	printf("\n\ntest_announce_withdraw_announce_twice\n\n");
	test_announce_withdraw_announce_twice(fresh_socket());

	return 0;
}
