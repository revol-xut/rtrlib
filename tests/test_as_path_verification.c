/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/aspa/aspa_array/aspa_array.h"

#include <string.h>
#include <assert.h>


#define ASNS(...) (uint32_t []) { __VA_ARGS__ }

#define RECORD(cas, providers) (struct aspa_record) { \
	.customer_asn = cas, \
	.provider_count = (size_t)(sizeof(providers) / sizeof(uint32_t)), \
	.provider_asns = sizeof(providers) == 0 ? NULL : providers \
}

#define ADD_OPERATION(idx, rec) ((struct aspa_update_operation) { \
	.index = idx, \
	.record = rec, \
	.type = ASPA_ADD, \
	.is_no_op = false \
})

#define BUILD_ASPA_TABLE(tablename, ...) \
	struct aspa_table *tablename = lrtr_malloc(sizeof(*tablename)); \
	assert(tablename != NULL); \
	aspa_table_init(tablename, NULL); \
	\
	NEW_SOCKET_ADD_RECORDS(tablename, __VA_ARGS__) \


#define _CAT_(a, b) a ## b
#define _CAT(a, b) _CAT_(a, b)
#define NEW_SOCKET_ADD_RECORDS(aspa_table, ...) { \
	struct rtr_socket *_CAT(rtr_socket, __LINE__) = lrtr_malloc(sizeof(struct rtr_socket)); \
	assert(_CAT(rtr_socket, __LINE__) != NULL); \
	_CAT(rtr_socket, __LINE__)->aspa_table = aspa_table; \
	\
	struct aspa_record records[] = { __VA_ARGS__ }; \
	size_t len = sizeof(records) / sizeof(struct aspa_record); \
	\
	if (len) { \
		struct aspa_update *update = NULL; \
		struct aspa_update_operation *operations = lrtr_malloc(len * sizeof(struct aspa_update_operation)); \
		for (size_t i = 0; i < len; i++) \
			operations[i] = ADD_OPERATION(i, records[i]); \
		\
		assert(aspa_table_update_swap_in_compute(aspa_table, _CAT(rtr_socket, __LINE__), operations, len, &update) == ASPA_SUCCESS); \
		aspa_table_update_swap_in_apply(update); \
		aspa_table_update_swap_in_finish(update); \
	} \
}

#define VERIFY_AS_PATH(aspa_table, direction, result, asns) \
	assert(result == aspa_verify_as_path(aspa_table, asns, sizeof(asns)/sizeof(uint32_t), direction));


static struct aspa_table *test_create_aspa_table()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	NEW_SOCKET_ADD_RECORDS(aspa_table,
		RECORD(100, ASNS(200, 201)),
		RECORD(200, ASNS(300)),
		RECORD(300, ASNS(400)),
		RECORD(400, ASNS(500)),

		RECORD(501, ASNS(601)),
		RECORD(401, ASNS(501)),
		RECORD(301, ASNS(401)),
		RECORD(201, ASNS(301)),

		RECORD(502, ASNS(602)),
		RECORD(402, ASNS(502)),
		RECORD(302, ASNS(402)),
		RECORD(202, ASNS(302)),

		// 103 --> 203 <--> 303 <--> 403 <-- 304
		RECORD(103, ASNS(203)),
		RECORD(203, ASNS(303)),
		RECORD(303, ASNS(203, 403)),
		RECORD(403, ASNS(303)),
		RECORD(304, ASNS(403)),
	);
	
	NEW_SOCKET_ADD_RECORDS(aspa_table,
		RECORD(100, ASNS(200, 202))
	);

	return aspa_table;
}

static void test_hopping(struct aspa_table* aspa_table) {
	// check that provider and not provider holds
	assert(aspa_check_hop(aspa_table, 100, 200) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 200, 100) == ASPA_NOT_PROVIDER_PLUS);

	assert(aspa_check_hop(aspa_table, 200, 300) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 500, 999) == ASPA_NO_ATTESTATION);

	assert(aspa_check_hop(aspa_table, 999, 999) == ASPA_NO_ATTESTATION);

	// multiple dissimilar aspas
	assert(aspa_check_hop(aspa_table, 100, 201) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 100, 202) == ASPA_PROVIDER_PLUS);
}

// test multiple routes
// - upstream (only customer-provider-hops)
//   - one not provider and one not attested: invalid
//   - one not attested: unknown
//   - all attested: valid

static void test_upstream(struct aspa_table* aspa_table) {
	// empty paths are valid
	assert(aspa_verify_as_path(aspa_table, NULL, 0, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);

	// paths of length 1 are valid
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(100));

	// valid upstream paths
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(200, 100));
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(300, 200));
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(300, 200, 100));

	// single not-provider hop (nP)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(999, 100));
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(300, 999, 100));
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(999, 999, 100));
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(999, 100, 999));

	// single unattested hop (nA)
	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(999, 500, 400, 300));
}

static void test_downstream(struct aspa_table* aspa_table) {
	// paths of length 1 <= N <= 2 are valid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(999));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(998, 999));

	// either up- or down-ramp is valid, not both
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(300, 400, 500));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(500, 400, 300));

	// w/o customer-provider gap
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(300, 400, 500, 400, 300));

	// single not-provider (nP) in between
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(302, 402, 502, 500, 400, 300));

	// two highest-level hops are nP
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(301, 401, 501, 502, 502, 402, 302));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(302, 402, 502, 999, 500, 400, 300));

	// single nA at highest level is valid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(999, 500, 400, 300));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(300, 400, 500, 999));

	// single nP at highest level is valid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(999, 502, 402, 302));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(302, 402, 502, 999));

	// the last hop in the down ramp must be valid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(999, 300, 400, 500));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(100, 300, 400, 500));

	// the first hop in the up ramp must be valid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(500, 400, 300, 999));
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(500, 400, 300, 100));

	// consecutive up-ramps are invalid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(400, 300, 200, 502, 402, 302));

	// consecutive down-ramps are invalid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(200, 300, 400, 302, 402, 502));

	// both down- and up-ramp are invalid
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(400, 300, 200, 302, 402, 502));

	// overlapping customer-provider-relationships
	// 103 --> 203 <--> 303 <--> 403 <-- 304
	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(304, 403, 303, 203, 103));

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 90, 40, 70, 80));
}

/**
 * Example 1 (downstream) (valid)
 *
 * as_path: 20, 30, 40, 70, 80
 *
 *          30   40
 *  10  20           70
 *                       80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_1()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(20, 30, 40, 70, 80));
}


/**
 * Example 2 (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30       40
 *  10   20       90      70
 *                           80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   90: 30, 40
 *
 */
static void test_verify_example_2()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
		RECORD(90, ASNS(30, 40)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 90, 40, 70, 80));
}


/**
 * Example 2b (downstream) (invalid)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30*      40*
 *  10  20       90      70
 *                           80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   90: 30, 40
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_2b()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
		RECORD(90, ASNS(30, 40)),
		RECORD(30, ASNS()),
		RECORD(40, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 90, 40, 70, 80));
}


/**
 * Example 3a (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30   90  40
 *      20               70
 *  10                       80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_3a()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 90, 40, 70, 80));
}


/**
 * Example 3b (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 100, 40, 70, 80
 *
 *          30   90  100 40
 *  10  20                 70
 *                            80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_3b()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 90, 100, 40, 70, 80));
}


/**
 * Example 3c (downstream) (invalid)
 *
 * as_path: 20, 30, 90, 100, 40, 70, 80
 *
 *       30*  90  100  40*
 *     20                 70
 *  10                      80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3c()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(40)),
		RECORD(20, ASNS(30)),
		RECORD(30, ASNS()),
		RECORD(40, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 90, 100, 40, 70, 80));
}


/**
 * Example 3d (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 100, 90, 70, 80
 *
 *         30*  40* 100? 90?
 *  10  20                  70
 *                            80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 90
 *   20: 30
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3d()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(90)),
		RECORD(20, ASNS(30)),
		RECORD(30, ASNS()),
		RECORD(40, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 40, 100, 90, 70, 80));
}


/**
 * Example 3f (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 100, 90, 70, 80
 *
 *          30   40  100 90
 *  10  20                 70
 *                            80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 90
 *   20: 30
 *   100:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3f()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(80, ASNS(70)),
		RECORD(70, ASNS(90)),
		RECORD(20, ASNS(30)),
		RECORD(100, ASNS()),
		RECORD(40, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 40, 100, 90, 70, 80));
}


/**
 * Example 4 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80
 *
 *  10                               80 (origin)
 *    20   30    40    50   60   70
 *
 * customer-providers:
 *   70: 80
 *
 */
static void test_verify_example_4()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(70, ASNS(80)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60, 70, 80));
}


/**
 * Example 4-fixed (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80
 *
 *  10                      80 (origin)
 *    20                70
 *      30  40  50  60
 *
 * customer-providers:
 *   70: 80
 *   60: 70
 *   30: 20
 *
 */
static void test_verify_example_4_fixed()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(70, ASNS(80)),
		RECORD(60, ASNS(70)),
		RECORD(30, ASNS(20)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60, 70, 80));
}


/**
 * Example 5 (upstream) (valid)
 *
 * as_path: 20, 30, 40
 *
 * 10  20
 *        30
 *           40 (origin)
 *
 * customer-providers:
 *   40: 30
 *   30: 20
 *
 */
static void test_verify_example_5()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(40, ASNS(30)),
		RECORD(30, ASNS(20)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(20, 30, 40));
}


/**
 * Example 6 (downstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120
 *
 *         50         90
 *       40  60 70 80   100
 *     30                  110
 *   20                       120
 * 10
 *
 * customer-providers:
 *   120: 110
 *   110: 100
 *   100: 90
 *   80: 90
 *   60: 50
 *   40: 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_6()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(120, ASNS(110)),
		RECORD(110, ASNS(100)),
		RECORD(100, ASNS(90)),
		RECORD(80, ASNS(90)),
		RECORD(60, ASNS(50)),
		RECORD(40, ASNS(50)),
		RECORD(30, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120));
}


/**
 * Example 7 (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140
 *
 * read from right: 100 -U-> 90 -U-> 80 -U-> 70 -U-> 60 -U-> 50
 * read from left: 50 -U-> 60 -U-> 70 -U-> 80 -P+-> 90 -P+-> 100
 * 
 *                        100
 *                     90     110
 *         50 60 70 80           120
 *       40                         130
 *     30                              140
 *   20
 * 10
 *
 * customer-providers:
 *   20: 30
 *   30: 40
 *   40: 50
 *   80: 90
 *   90: 100
 *   110: 100
 *   120: 110
 *   130: 120
 *   140: 130
 *
 */
static void test_verify_example_7()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(20, ASNS(30)),
		RECORD(30, ASNS(40)),
		RECORD(40, ASNS(50)),
		RECORD(80, ASNS(90)),
		RECORD(90, ASNS(100)),
		RECORD(110, ASNS(100)),
		RECORD(120, ASNS(110)),
		RECORD(130, ASNS(120)),
		RECORD(140, ASNS(130)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140));
}


/**
 * Example 8 (downstream) (valid)
 *
 * as_path: 20
 *
 *   20
 * 10
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_8()
{
	BUILD_ASPA_TABLE(aspa_table,
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(20));
}


/**
 * Example 9 (upstream) (valid)
 *
 * as_path: 20
 *
 * 10
 *   20
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_9()
{
	BUILD_ASPA_TABLE(aspa_table,
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_VALID,
		ASNS(20));
}


/**
 * Example 11 (downstream) (valid)
 *
 * as_path: 20, 30
 *
 *   20 30
 *
 * customer-providers:
 *   20:   (none)
 *   30:   (none)
 *
 */
static void test_verify_example_11()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(20, ASNS()),
		RECORD(30, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_DOWNSTREAM, ASPA_AS_PATH_VALID,
		ASNS(20, 30));
}


/**
 * Example 12 (upstream) (unknown)
 *
 * as_path: 20, 30
 *
 *   20 30
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_12()
{
	BUILD_ASPA_TABLE(aspa_table,
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_UNKNOWN,
		ASNS(20, 30));
}


/**
 * Example 13 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *   20
 *      30
 *         40  50
 *               60
 *
 * customer-providers:
 *   60: 50
 *   50:   (none)
 *   40: 30
 *   30: 20
 *   20:   (none)
 *
 */
static void test_verify_example_13()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(60, ASNS(50)),
		RECORD(50, ASNS()),
		RECORD(40, ASNS(30)),
		RECORD(30, ASNS(20)),
		RECORD(20, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60));
}


/**
 * Example 14 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *     30 <> 40 <> 50 <> 60
 *  20         
 *
 * customer-providers:
 *   60: 50
 *   50: 40, 60
 *   40: 30, 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_14()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(60, ASNS(50)),
		RECORD(50, ASNS(40, 60)),
		RECORD(40, ASNS(30, 50)),
		RECORD(30, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60));
}


/**
 * Example 15 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *       30 <> 40 <> 50 <> 60
 *   20
 *
 * customer-providers:
 *   60: 50, 20
 *   50: 40, 60
 *   40: 30, 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_15()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(60, ASNS(50, 20)),
		RECORD(50, ASNS(40, 60)),
		RECORD(40, ASNS(30, 50)),
		RECORD(30, ASNS(40)),
		RECORD(20, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(20, 30, 40, 50, 60));
}


/**
 * Example 16 (upstream) (invalid)
 *
 * as_path: 10, 20, 30, 40
 *
 *     20   30
 * 10           40
 *
 * customer-providers:
 *   10: 20
 *   20: 100
 *   40: 30
 *
 */
static void test_verify_example_16()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(10, ASNS(20)),
		RECORD(20, ASNS(100)),
		RECORD(40, ASNS(30)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(10, 20, 30, 40));
}


/**
 * Example 17 (upstream) (invalid)
 *
 * as_path: 10, 20, 30, 40
 *
 *                 X
 *     20      40
 * 10      30
 *
 * customer-providers:
 *   10: 20
 *   20: 100
 *   40: 30, 50
 *   50: 40
 *
 */
static void test_verify_example_17()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(10, ASNS(20)),
		RECORD(20, ASNS(100)),
		RECORD(40, ASNS(30, 50)),
		RECORD(50, ASNS(40)),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(10, 20, 30, 40));
}


/**
 * Example 18 (upstream) (invalid)
 *
 * as_path: 30, 20, 40
 *
 *  30  20*  40
 *
 * customer-providers:
 *   20:   (none)
 *
 */
static void test_verify_example_18()
{
	BUILD_ASPA_TABLE(aspa_table,
		RECORD(20, ASNS()),
	)

	VERIFY_AS_PATH(aspa_table, ASPA_UPSTREAM, ASPA_AS_PATH_INVALID,
		ASNS(30, 20, 40));
}

static void test_single_collapse(uint32_t input[], size_t input_len, uint32_t output[], size_t output_len)
{
	size_t retlen = aspa_collapse_as_path(input, input_len);
	assert(retlen == output_len);
	for (size_t i = 0; i < output_len; i++) {
		assert(input[i] == output[i]);
	}
}

static void test_collapse()
{
	test_single_collapse(NULL, 0, NULL, 0);
	test_single_collapse((uint32_t []){1}, 1, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 1}, 2, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 2}, 2, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 1, 1}, 3, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 1, 2}, 3, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2}, 3, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2, 2}, 4, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2, 3}, 4, (uint32_t []){1, 2, 3}, 3);
}

int main()
{
	struct aspa_table *aspa_table = test_create_aspa_table();
	test_hopping(aspa_table);
	test_upstream(aspa_table);
	test_downstream(aspa_table);

	test_verify_example_1();
	test_verify_example_2();
	test_verify_example_2b();
	test_verify_example_3a();
	test_verify_example_3b();
	test_verify_example_3c();
	test_verify_example_3d();
	test_verify_example_3f();
	test_verify_example_4();
	test_verify_example_4_fixed();
	test_verify_example_5();
	test_verify_example_6();
	test_verify_example_7();
	test_verify_example_8();
	test_verify_example_9();
	test_verify_example_11();
	test_verify_example_12();
	test_verify_example_13();
	test_verify_example_14();
	test_verify_example_15();
	test_verify_example_16();
	test_verify_example_17();
	test_verify_example_18();


	test_collapse();
}
