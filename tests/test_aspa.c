/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website; http://rtrlib.realmv6.org/
 */

#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/lib/convert_byte_order_private.h"
#include "rtrlib/pfx/pfx_private.h"
#include "rtrlib/rtr/packets_private.h"
#include "rtrlib/rtr/rtr_pdus.h"
#include "rtrlib/spki/hashtable/ht-spkitable_private.h"
#include "rtrlib/transport/transport.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

char *data;
size_t data_size = 0;
size_t data_index = 0;

bool assert_callbacks = true;
struct update_callback *expected_callbacks;
size_t callback_index;
size_t callback_count;

struct update_callback {
	struct aspa_table *source;
	struct aspa_record record;
	enum aspa_operation_type type;
};

#define BYTES16(X) lrtr_convert_short(TO_HOST_HOST_BYTE_ORDER, X)
#define BYTES32(X) lrtr_convert_long(TO_HOST_HOST_BYTE_ORDER, X)

#define ASNS(...) ((uint32_t[]){__VA_ARGS__})

// clang-format off

#define APPEND_ASPA(version, flag, cas, providers) \
	append_aspa(version, flag, cas, sizeof(providers) == 0 ? NULL : providers, \
		    (size_t)(sizeof(providers) / sizeof(uint32_t)))

#define RECORD(cas, providers) \
	((struct aspa_record){.customer_asn = cas, \
			      .provider_count = (size_t)(sizeof(providers) / sizeof(uint32_t)), \
			      .provider_asns = sizeof(providers) == 0 ? NULL : providers})

#define _CAT_(a, b) a##b
#define _CAT(a, b) _CAT_(a, b)
#define _LINEVAR(V) _CAT(V, __LINE__)

#define ASSERT_TABLE(socket, ...) \
	struct aspa_record _LINEVAR(_records)[] = {__VA_ARGS__}; \
	assert_table(socket, _LINEVAR(_records), (size_t)(sizeof(_LINEVAR(_records)) / sizeof(struct aspa_record)))

#define ASSERT_EMPTY_TABLE(socket, ...) assert_table(socket, NULL, 0)

#define ADDED(rec) ((struct update_callback){.source = NULL, .record = rec, .type = ASPA_ADD})

#define ADDED_TO(table, rec) ((struct update_callback){.source = table, .record = rec, .type = ASPA_ADD})

#define REMOVED(rec) ((struct update_callback){.source = NULL, .record = rec, .type = ASPA_REMOVE})

#define REMOVED_FROM(table, rec) ((struct update_callback){.source = table, .record = rec, .type = ASPA_REMOVE})

#define EXPECT_UPDATE_CALLBACKS(...) \
	struct update_callback _LINEVAR(_callbacks)[] = {__VA_ARGS__}; \
	expect_update_callbacks(_LINEVAR(_callbacks), \
				(size_t)(sizeof(_LINEVAR(_callbacks)) / sizeof(struct update_callback)))

// clang-format on

#define ASPA_ANNOUNCE 1
#define ASPA_WITHDRAW 0

static int custom_send(const struct tr_socket *socket __attribute__((unused)), const void *pdu, const size_t len,
		       const time_t timeout __attribute__((unused)))
{
	const struct pdu_error *err = pdu;

	if (err->type == 10) {
		uint32_t *errlen = (uint32_t *)((char *)err->rest + err->len_enc_pdu);

		if ((char *)errlen < (char *)err + BYTES32(err->len))
			printf("err msg: %.*s\n", *errlen, (char *)(errlen + 1));
	}
	return len;
}

static int custom_recv(const struct tr_socket *socket __attribute__((unused)), const void *buf, const size_t len,
		       const time_t timeout __attribute__((unused)))
{
	size_t rlen = len;

	if (data_index + rlen > data_size)
		rlen = data_size - data_index;

	memcpy((char *)buf, data + data_index, rlen);
	data_index += rlen;
	return rlen;
}

static struct pdu_cache_response *begin_cache_response(uint8_t version, uint16_t session_id)
{
	if (!data)
		data = lrtr_malloc(sizeof(struct pdu_cache_response));
	else
		data = lrtr_realloc(data, data_size + sizeof(struct pdu_cache_response));

	assert(data);

	struct pdu_cache_response *cache_response = (struct pdu_cache_response *)(data + data_size);

	cache_response->ver = version;
	cache_response->type = CACHE_RESPONSE;
	cache_response->session_id = BYTES16(session_id);
	cache_response->len = BYTES32(8);

	data_size += sizeof(struct pdu_cache_response);

	return cache_response;
}

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
	aspa->len = BYTES32(pdu_size);
	aspa->flags = flags;
	aspa->afi_flags = 0x3;
	aspa->provider_count = BYTES16((uint16_t)provider_count);
	aspa->customer_asn = BYTES32(customer_asn);

	for (size_t i = 0; i < provider_count; i++)
		provider_asns[i] = BYTES32(provider_asns[i]);

	if (provider_asns)
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
	eod->session_id = BYTES16(session_id);
	eod->len = BYTES32(24);
	eod->sn = BYTES32(sn);
	eod->refresh_interval = BYTES32(RTR_REFRESH_MIN);
	eod->retry_interval = BYTES32(RTR_RETRY_MIN);
	eod->expire_interval = BYTES32(RTR_EXPIRATION_MIN);

	data_size += sizeof(struct pdu_end_of_data_v1_v2);

	return eod;
}

static void clear_expected_callbacks(void)
{
	expected_callbacks = NULL;
	callback_index = 0;
	callback_count = 0;
}

static void expect_update_callbacks(struct update_callback callbacks[], size_t count)
{
	clear_expected_callbacks();

	if (callbacks && count > 0) {
		expected_callbacks = callbacks;
		callback_count = count;
		callback_index = 0;
	} else {
		expected_callbacks = NULL;
		callback_count = 0;
		callback_index = 0;
	}
}

static void aspa_update_callback(struct aspa_table *s, const struct aspa_record record,
				 const struct rtr_socket *rtr_sockt __attribute__((unused)),
				 const enum aspa_operation_type operation_type)
{
	if (assert_callbacks) {
		assert(callback_count > 0);
		assert(callback_index < callback_count);
		assert(expected_callbacks);

		if (expected_callbacks[callback_index].source) {
			if (expected_callbacks[callback_index].source != s)
				printf("Assertion failed: Callback originates from unexpected table.\n");

			assert(expected_callbacks[callback_index].source == s);
		}

		assert(expected_callbacks[callback_index].record.customer_asn == record.customer_asn);
		assert(expected_callbacks[callback_index].type == operation_type);
		assert(expected_callbacks[callback_index].record.provider_count == record.provider_count);

		for (size_t k = 0; k < record.provider_count; k++)
			assert(expected_callbacks[callback_index].record.provider_asns[k] == record.provider_asns[k]);

		callback_index += 1;
	}

	char c;

	switch (operation_type) {
	case ASPA_ADD:
		c = '+';
		break;
	case ASPA_REMOVE:
		c = '-';
		break;
	default:
		break;
	}

	printf("%c ASPA ", c);
	printf("%u => [ ", record.customer_asn);

	size_t i;
	size_t count = record.provider_count;

	for (i = 0; i < count; i++) {
		printf("%u", record.provider_asns[i]);
		if (i < count - 1)
			printf(", ");
	}

	printf(" ]\n");
}

static void assert_table(struct rtr_socket *socket, struct aspa_record records[], size_t record_count)
{
	assert(socket->aspa_table);
	assert(socket->aspa_table->store);
	assert(socket->aspa_table->store->aspa_array);
	assert(socket->aspa_table->store->rtr_socket);
	assert(socket->aspa_table->store->rtr_socket == socket);
	assert(socket->aspa_table->store->next == NULL);

	struct aspa_array *array = socket->aspa_table->store->aspa_array;

	if (array->size != record_count)
		printf("error!");
	assert(array->size == record_count);

	if (record_count <= 0)
		return;

	assert(records);
	assert(array->data);

	for (size_t i = 0; i < record_count; i++) {
		assert(array->data[i].customer_asn == records[i].customer_asn);
		assert(array->data[i].provider_count == records[i].provider_count);

		for (size_t k = 0; k < records[i].provider_count; k++)
			assert(array->data[i].provider_asns[k] == records[i].provider_asns[k]);
	}
}

// clang-format off
static void test_regular_announcement(struct rtr_socket *socket)
{
	// Test: regular announcement
	// Expect: OK
	// DB: inserted
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1101, 1102, 1103, 1104));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(1101, 1102, 1103, 1104)));
}

static void test_withdraw(struct rtr_socket *socket)
{
	// Test: Withdraw existing record
	// Expect: OK
	// DB: record gets removed

	// Announces 1100 => 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, ASNS(42));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	EXPECT_UPDATE_CALLBACKS(
		REMOVED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_EMPTY_TABLE(socket);
}

static void test_regular_announcements(struct rtr_socket *socket)
{
	// Test: regular announcement
	// Expect: OK
	// DB: inserted
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1101, 1102, 1103, 1104));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 4400, ASNS(4401));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED(RECORD(4400, ASNS(4401))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1100, ASNS(1101, 1102, 1103, 1104)),
		RECORD(4400, ASNS(4401))
	);
}

static void test_announce_existing(struct rtr_socket *socket)
{
	// Test: Announce for existing customer_asn
	// Expect: ERROR
	// DB: no change

	// Announces 1100 => 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(2201, 2202, 2203, 2204));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// No updates expected, fails at first PDU
	EXPECT_UPDATE_CALLBACKS();

	assert(rtr_sync(socket) == RTR_ERROR);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(1101, 1102, 1103, 1104)));
}

static void test_announce_twice(struct rtr_socket *socket)
{
	// Test: Announce new record again (duplicate)
	// Expect: ERROR
	// DB: no change

	// Announces 1100 => 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1101, 1102, 1103, 1104));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// No updates expected, fails at first PDU
	EXPECT_UPDATE_CALLBACKS();

	assert(rtr_sync(socket) == RTR_ERROR);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(1101, 1102, 1103, 1104)));
}

static void test_withdraw_nonexisting(struct rtr_socket *socket)
{
	// Test: Withdraw non-existent record
	// Expect: ERROR
	// DB: no change

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 3300, ASNS());
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// No updates expected, fails at first PDU
	EXPECT_UPDATE_CALLBACKS();

	assert(rtr_sync(socket) == RTR_ERROR);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(1101, 1102, 1103, 1104)));
}

static void test_announce_withdraw(struct rtr_socket *socket)
{
	// Test: Announce record, immediately withdraw within same sync op
	// Expect: OK
	// DB: no change

	// Announces 1100 => 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, ASNS(3301, 3302, 3303, 3304));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 3300, ASNS());
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

#if ASPA_NOTIFY_NO_OPS
	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(3300, ASNS(3301, 3302, 3303, 3304))),
		REMOVED(RECORD(3300, ASNS(3301, 3302, 3303, 3304))),
	);
#else
	EXPECT_UPDATE_CALLBACKS();
#endif

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(1101, 1102, 1103, 1104)));
}

static void test_withdraw_announce(struct rtr_socket *socket)
{
	// Test: Withdraw existing record, immediately announce record with
	// same ASN within same sync op, include no-op
	// Expect: OK
	// DB: record gets replaced

	// announces 1100 -> 1101, 1102, 1103, 1104
	test_regular_announcement(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, ASNS());
	// The following two are complementary (no-op)
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(2201, 2202, 2203, 2204));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(2201, 2202, 2203, 2204));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

#if ASPA_NOTIFY_NO_OPS
	EXPECT_UPDATE_CALLBACKS(
		REMOVED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED(RECORD(1100, ASNS(2201, 2202, 2203, 2204))),
		REMOVED(RECORD(1100, ASNS(2201, 2202, 2203, 2204))),
		ADDED(RECORD(1100, ASNS(2201, 2202, 2203, 2204))),
	);
#else
	EXPECT_UPDATE_CALLBACKS(
		REMOVED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED(RECORD(1100, ASNS(2201, 2202, 2203, 2204))),
	);
#endif

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket, RECORD(1100, ASNS(2201, 2202, 2203, 2204)));
}

static void test_regular(struct rtr_socket *socket)
{
	// Test: regular announcements and withdrawals
	// Expect: OK
	// DB: withdrawn records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1101, 1102, 1103, 1104));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1101, ASNS(1100, 1102, 1103, 1104));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 2200, ASNS(2201, 2202, 2203, 2204));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED(RECORD(1101, ASNS(1100, 1102, 1103, 1104))),
		ADDED(RECORD(2200, ASNS(2201, 2202, 2203, 2204))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1100, ASNS(1101, 1102, 1103, 1104)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(2200, ASNS(2201, 2202, 2203, 2204)),
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, ASNS(3301, 3302, 3303, 3304));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(3300, ASNS(3301, 3302, 3303, 3304))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1100, ASNS(1101, 1102, 1103, 1104)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(2200, ASNS(2201, 2202, 2203, 2204)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304))
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1100, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 2200, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1201, 1202, 1203, 1204));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 0, ASNS());
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(0, ASNS())),
		REMOVED(RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED(RECORD(1100, ASNS(1201, 1202, 1203, 1204))),
		REMOVED(RECORD(2200, ASNS(2201, 2202, 2203, 2204))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(0, ASNS()),
		RECORD(1100, ASNS(1201, 1202, 1203, 1204)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304)),
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	// The following two are complementary (no-op)
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1901, ASNS(1201, 1202, 1203, 1204));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1901, ASNS());
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

#if ASPA_NOTIFY_NO_OPS
	printf("Notifying No-Ops!");
	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1901, ASNS(1201, 1202, 1203, 1204))),
		REMOVED(RECORD(1901, ASNS(1201, 1202, 1203, 1204))),
	);
#else
	printf("Ignoring No-Ops!");
	EXPECT_UPDATE_CALLBACKS();
#endif

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(0, ASNS()),
		RECORD(1100, ASNS(1201, 1202, 1203, 1204)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304)),
	);
}

static void test_regular_swap(struct rtr_socket *socket)
{
	test_regular(socket);

	ASSERT_TABLE(socket,
		RECORD(0, ASNS()),
		RECORD(1100, ASNS(1201, 1202, 1203, 1204)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304)),
	);

	struct aspa_table *src_table = socket->aspa_table;
	struct aspa_table *dst_table = lrtr_calloc(1, sizeof(struct aspa_table));

	assert(dst_table);
	aspa_table_init(dst_table, aspa_update_callback);
	socket->aspa_table = dst_table;

	printf("creating existing data, soon to be overwritten...\n");

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1100, ASNS(1101, 1102, 1103, 1104));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 4400, ASNS(4401));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED_TO(dst_table, RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		ADDED_TO(dst_table, RECORD(4400, ASNS(4401)))
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1100, ASNS(1101, 1102, 1103, 1104)),
		RECORD(4400, ASNS(4401))
	);

	socket->aspa_table = src_table;

	printf("swapping...\n");

	EXPECT_UPDATE_CALLBACKS(
		// records in existing table will be removed...
		REMOVED_FROM(src_table, RECORD(0, ASNS())),
		REMOVED_FROM(src_table, RECORD(1100, ASNS(1201, 1202, 1203, 1204))),
		REMOVED_FROM(src_table, RECORD(1101, ASNS(1100, 1102, 1103, 1104))),
		REMOVED_FROM(src_table, RECORD(3300, ASNS(3301, 3302, 3303, 3304))),

		// records in new table will be replaced (removed, then added)
		REMOVED_FROM(dst_table, RECORD(1100, ASNS(1101, 1102, 1103, 1104))),
		REMOVED_FROM(dst_table, RECORD(4400, ASNS(4401))),

		// record previously removed from the existing table are added to new table
		ADDED_TO(dst_table, RECORD(0, ASNS())),
		ADDED_TO(dst_table, RECORD(1100, ASNS(1201, 1202, 1203, 1204))),
		ADDED_TO(dst_table, RECORD(1101, ASNS(1100, 1102, 1103, 1104))),
		ADDED_TO(dst_table, RECORD(3300, ASNS(3301, 3302, 3303, 3304))),
	);

	assert(aspa_table_src_replace(dst_table, src_table, socket, true, true) == ASPA_SUCCESS);
	assert(callback_index == callback_count);

	aspa_table_free(dst_table, false);
}

static void test_withdraw_twice(struct rtr_socket *socket)
{
	// Test: duplicate in-sequence withdrawal
	// Expect: Error
	// DB: records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1900, ASNS(1901, 1902, 1903, 1904));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1901, ASNS(1900, 1902, 1903, 1904));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 2200, ASNS(2201, 2202, 2203, 2204));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1900, ASNS(1901, 1902, 1903, 1904))),
		ADDED(RECORD(1901, ASNS(1900, 1902, 1903, 1904))),
		ADDED(RECORD(2200, ASNS(2201, 2202, 2203, 2204))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1900, ASNS(1901, 1902, 1903, 1904)),
		RECORD(1901, ASNS(1900, 1902, 1903, 1904)),
		RECORD(2200, ASNS(2201, 2202, 2203, 2204)),
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 3300, ASNS(3301, 3302, 3303, 3304));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(3300, ASNS(3301, 3302, 3303, 3304))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1900, ASNS(1901, 1902, 1903, 1904)),
		RECORD(1901, ASNS(1900, 1902, 1903, 1904)),
		RECORD(2200, ASNS(2201, 2202, 2203, 2204)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304))
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1900, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 2200, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1900, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1900, ASNS(1201, 1202, 1203, 1204));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 0, ASNS());
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// Callback behavior deviates for different update mechanisms
	// Swap-In: No callback because update computation fails
	// In-Place: Callbacks until failed operation, then callbacks from undo
	assert_callbacks = false;
	assert(rtr_sync(socket) == RTR_ERROR);
	assert_callbacks = true;

	ASSERT_TABLE(socket,
		RECORD(1900, ASNS(1901, 1902, 1903, 1904)),
		RECORD(1901, ASNS(1900, 1902, 1903, 1904)),
		RECORD(2200, ASNS(2201, 2202, 2203, 2204)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304)),
	);
}

static void test_announce_withdraw_announce_twice(struct rtr_socket *socket)
{
	// Test: regular announcements and withdrawals
	// Expect: OK
	// DB: records get removed, newly announced are added

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, ASNS(1401, 1402, 1403, 1404));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1400, ASNS(1401, 1402, 1403, 1404))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);

	ASSERT_TABLE(socket,
		RECORD(1400, ASNS(1401, 1402, 1403, 1404)),
	);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, 1400, ASNS());
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, ASNS(1201, 1202, 1203, 1204));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1400, ASNS(1201, 1202, 1203));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// Callback behavior deviates for different update mechanisms
	// Swap-In: No callback because update computation fails
	// In-Place: Callbacks until failed operation, then callbacks from undo
	assert_callbacks = false;
	assert(rtr_sync(socket) == RTR_ERROR);
	assert_callbacks = true;

	ASSERT_TABLE(socket,
		RECORD(1400, ASNS(1401, 1402, 1403, 1404)),
	);
}

static void test_long(struct rtr_socket *socket)
{
	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 1, ASNS(2, 3, 4, 5));
	APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 2, ASNS(3, 4, 5, 6));
	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 437);

	EXPECT_UPDATE_CALLBACKS(
		ADDED(RECORD(1, ASNS(2, 3, 4, 5))),
		ADDED(RECORD(2, ASNS(3, 4, 5, 6))),
	);

	assert(rtr_sync(socket) == RTR_SUCCESS);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(1, ASNS(2, 3, 4, 5)),
		RECORD(2, ASNS(3, 4, 5, 6)),
	);

	uint32_t provider_asns[2056 * 4 + 3];

	for (int i = 1; i < 1028; i++) {
		uint32_t base = 2 * i;

		begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
		APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_WITHDRAW, i,
			ASNS());

		APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, base + 1,
			ASNS(base + 2, base + 3, base + 4, base + 5));

		APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, base + 2,
			ASNS(base + 3, base + 4, base + 5, base + 6));

		end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

		EXPECT_UPDATE_CALLBACKS(
			REMOVED(RECORD(i, ASNS(i + 1, i + 2, i + 3, i + 4))),
			ADDED(RECORD(base + 1, ASNS(base + 2, base + 3, base + 4, base + 5))),
			ADDED(RECORD(base + 2, ASNS(base + 3, base + 4, base + 5, base + 6))),
		);
		assert(rtr_sync(socket) == RTR_SUCCESS);
		assert(callback_index == callback_count);

		size_t record_count = i + 2;

		struct aspa_record records[record_count];

		for (uint32_t customer_asn = i + 1; customer_asn <= base + 2; customer_asn++) {
			for (int k = 0; k < 4; k++)
				provider_asns[4 * customer_asn + k] = customer_asn + k + 1;

			records[customer_asn - i - 1] =
				((struct aspa_record) {
					.customer_asn = customer_asn,
					.provider_count = 4,
					.provider_asns = &provider_asns[4 * customer_asn]
				});
		}
		assert_table(socket, records, record_count);
	}
}

static void test_corrupt(struct rtr_socket *socket)
{
	// Test: send corrupt pdu after having received valid data
	// Expect: Error
	// DB: DB stays the same

	test_regular(socket);

	begin_cache_response(RTR_PROTOCOL_VERSION_2, 0);
	struct pdu_aspa *aspa =
		APPEND_ASPA(RTR_PROTOCOL_VERSION_2, ASPA_ANNOUNCE, 4400, ASNS(4401, 4402, 4403, 4404));

	// corrupt ASPA len
	aspa->len = BYTES32(BYTES32(aspa->len) + 1);

	end_cache_response(RTR_PROTOCOL_VERSION_2, 0, 444);

	// No updates expected, fails at first PDU
	EXPECT_UPDATE_CALLBACKS();
	assert(rtr_sync(socket) == RTR_ERROR);
	assert(callback_index == callback_count);

	ASSERT_TABLE(socket,
		RECORD(0, ASNS()),
		RECORD(1100, ASNS(1201, 1202, 1203, 1204)),
		RECORD(1101, ASNS(1100, 1102, 1103, 1104)),
		RECORD(3300, ASNS(3301, 3302, 3303, 3304))
	);
}

// clang-format off

static void cleanup(struct rtr_socket **socket)
{
	printf("cleaning...\n");

	if (data) {
		lrtr_free(data);
		data = NULL;
		data_size = 0;
		data_index = 0;
	}

	if (socket && *socket) {
		if ((*socket)->aspa_table)
			aspa_table_free((*socket)->aspa_table, false);

		if ((*socket)->tr_socket)
			lrtr_free((*socket)->tr_socket);

		lrtr_free(*socket);

		*socket = NULL;
	}

	clear_expected_callbacks();
}

static struct rtr_socket *create_socket(bool is_resetting)
{
	struct tr_socket *tr_socket = lrtr_calloc(1, sizeof(struct tr_socket));

	tr_socket->recv_fp = (tr_recv_fp) &custom_recv;
	tr_socket->send_fp = (tr_send_fp) &custom_send;

	struct rtr_socket *socket = lrtr_calloc(1, sizeof(struct rtr_socket));

	assert(socket);
	socket->is_resetting = is_resetting;
	socket->version = 2;
	socket->state = RTR_SYNC;
	socket->tr_socket = tr_socket;

	struct aspa_table *aspa_table = lrtr_calloc(1, sizeof(struct aspa_table));

	assert(aspa_table);
	aspa_table_init(aspa_table, aspa_update_callback);
	socket->aspa_table = aspa_table;

	struct spki_table *spki_table = lrtr_malloc(sizeof(struct spki_table));

	spki_table_init(spki_table, NULL);
	socket->spki_table = spki_table;

	struct pfx_table *pfx_table = lrtr_malloc(sizeof(struct pfx_table));

	pfx_table_init(pfx_table, NULL);
	socket->pfx_table = pfx_table;

	return socket;
}

static void run_tests(bool is_resetting)
{
	struct rtr_socket *socket = NULL;

	cleanup(&socket);

	printf("\nTEST: test_regular_announcement\n");
	socket = create_socket(is_resetting);
	test_regular_announcement(socket);

	cleanup(&socket);

	printf("\nTEST: regular_announcement\n");
	socket = create_socket(is_resetting);
	test_regular_announcement(socket);

	cleanup(&socket);

	printf("\nTEST: regular_announcements\n");
	socket = create_socket(is_resetting);
	test_regular_announcements(socket);

	cleanup(&socket);

	printf("\nTEST: withdraw\n");
	socket = create_socket(is_resetting);
	test_withdraw(socket);

	cleanup(&socket);

	printf("\nTEST: announce_existing\n");
	socket = create_socket(is_resetting);
	test_announce_existing(socket);

	printf("\nTEST: announce_twice\n");
	socket = create_socket(is_resetting);
	test_announce_twice(socket);

	cleanup(&socket);

	printf("\nTEST: withdraw_nonexisting\n");
	socket = create_socket(is_resetting);
	test_withdraw_nonexisting(socket);

	cleanup(&socket);

	printf("\nTEST: announce_withdraw\n");
	socket = create_socket(is_resetting);
	test_announce_withdraw(socket);

	cleanup(&socket);

	printf("\nTEST: withdraw_announce\n");
	socket = create_socket(is_resetting);
	test_withdraw_announce(socket);

	cleanup(&socket);

	printf("\nTEST: regular\n");
	socket = create_socket(is_resetting);
	test_regular(socket);

	cleanup(&socket);

	printf("\nTEST: regular_swap\n");
	socket = create_socket(is_resetting);
	test_regular_swap(socket);

	cleanup(&socket);

	printf("\nTEST: withdraw_twice\n");
	socket = create_socket(is_resetting);
	test_withdraw_twice(socket);

	cleanup(&socket);

	printf("\nTEST: corrupt\n");
	socket = create_socket(is_resetting);
	test_corrupt(socket);

	cleanup(&socket);

	printf("\nTEST: announce_withdraw_announce_twice\n");
	socket = create_socket(is_resetting);
	test_announce_withdraw_announce_twice(socket);

	cleanup(&socket);

	printf("\nTEST: long\n");
	socket = create_socket(is_resetting);
	test_long(socket);

	cleanup(&socket);
}

int main(void)
{
	run_tests(false);

	printf("\n\nTesting with atomic reset...\n");
	run_tests(true);
}
