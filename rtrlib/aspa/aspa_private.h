/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

/**
 * @defgroup mod_aspa_h ASPA validation table
 *
 * @brief The aspa_table is an abstract data structure to organize the validated Autonomous System Provider Authorization  data
 * received from an RPKI-RTR cache server.
 *
 * @{
 */

#ifndef RTR_ASPA_PRIVATE_H
#define RTR_ASPA_PRIVATE_H

#include "aspa.h"

#include "rtrlib/rtr/rtr.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief A linked list storing the bond between a socket and an @c aspa_array .
 */
struct aspa_store_node {
	struct aspa_array *aspa_array;
	struct rtr_socket *rtr_socket;
	struct aspa_store_node *next;
};

/**
 * @brief Replaces all ASPA records associated with the given socket with the records in the src table.
 * @param[in,out] dst The destination table. Existing records associated with the socket are replaced.
 * @param[in,out] src The source table.
 * @param[in,out] rtr_socket The socket the records are associated with.
 * @param notify_dst A boolean value determining whether to notify the destination tables' clients.
 * @param notify_src A boolean value determining whether to notify the source tables' clients.
 */
enum aspa_status aspa_table_src_replace(struct aspa_table *dst, struct aspa_table *src, struct rtr_socket *rtr_socket,
					bool notify_dst, bool notify_src);

// MARK: - Updating

/**
 * @brief A struct describing a specific type of operation that should be performed using the attached ASPA record.
 * @param index A value uniquely identifying this operation's position within the array of operations.
 * @param type The operation's type.
 * @param record The record that should be added or removed.
 */
struct aspa_update_operation {
	size_t index;
	enum aspa_operation_type type;
	bool skip;
	struct aspa_record record;
};

// MARK: - Swap-In Update Mechanism

/**
 * @brief Computed ASPA update.
 */
struct aspa_update {
	struct aspa_table *table;
	struct aspa_update_operation *operations;
	size_t operation_count;
	struct aspa_store_node *node;
	struct aspa_array *new_array;
	struct aspa_array *old_array;
	bool is_applied;
};

/**
 * @brief Computes an update structure that can later be applied to the given ASPA table.
 *
 * @note Each record in an 'add' operation may have a provider array associated with it. Any record in a 'remove' operation must have its @c provider_count set to 0 and @c provider_array set to @c NULL .
 * @note You should not release the operations array or any associated provider arrays yourself. Instead, rely on calling `aspa_table_update_cleanup` which deallocates both unused provider arrays and the operations array. The ASPA table avoids unnecessarily copying provider arrays and re-uses them instead.
 *
 * @param[in] aspa_table ASPA table to store new ASPA data in.
 * @param[in] rtr_socket The socket the updates originate from.
 * @param[in] operations  Add and remove operations to perform.
 * @param[in] count  Number of operations.
 * @param[in,out] failed_operation The operation responsible for causing the table update failure. @c NULL , if the update succeeded.
 * @param update The computed update. The update pointer must be non-NULL, but may point to a @c NULL value initially. After the update is computed this pointer points to an initialized update structure.
 * @return @c ASPA_SUCCESS On success.
 * @return @c ASPA_RECORD_NOT_FOUND If a records is supposed to be removed but cannot be found.
 * @return @c ASPA_DUPLICATE_RECORD If a records is supposed to be added but its corresponding customer ASN already exists.
 * @return @c ASPA_ERROR On on failure.
 *
 */
enum aspa_status aspa_table_compute_update(struct aspa_table *aspa_table, struct rtr_socket *rtr_socket,
					   struct aspa_update_operation *operations, size_t count,
					   struct aspa_update_operation **failed_operation,
					   struct aspa_update **update);

/**
 * @brief Applys the given update, as previously computed by @c aspa_table_compute_update
 * @param update The update that will be applied.
 */
void aspa_table_apply_update(struct aspa_update *update);

/**
 * @brief Frees the given update and unused provider arrays.
 * @param update The update struct to free
 */
void aspa_table_update_cleanup(struct aspa_update *update);

// MARK: - Verification

enum aspa_hop_result { ASPA_NO_ATTESTATION, ASPA_NOT_PROVIDER_PLUS, ASPA_PROVIDER_PLUS };

/**
 * @brief Checks a hop in the given @c AS_PATH .
 * @return @c aspa_hop_result .
 */
enum aspa_hop_result aspa_check_hop(struct aspa_table *aspa_table, uint32_t customer_asn, uint32_t provider_asn);

#endif
/** @} */
