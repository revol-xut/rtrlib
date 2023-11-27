/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/aspa/aspa.h"
#include "rtrlib/aspa/aspa_array/aspa_array.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

static char *buffer_file(char *fname) {
    FILE *f = fopen(fname, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    char *string = lrtr_malloc(fsize+4);
    fread(string, fsize, 1, f);
    *(uint32_t*)(&string[fsize]) = 0;
    fclose(f);
    return string;
}

enum as_path_verification_result *verify_as_path(struct aspa_table *aspa_table, struct rtr_socket* rtr_socket, char* f, size_t batch_size){
    uint32_t nwalks = *(uint32_t*)(&f[0]);
    long pos = sizeof(uint32_t);

    uint32_t plen = *(uint32_t*)(&f[pos]);
    pos += sizeof(uint32_t);

    enum as_path_verification_result *results = (enum as_path_verification_result*)lrtr_malloc(sizeof(enum as_path_verification_result)*nwalks*plen/batch_size);

    for (int i = 0; i < nwalks; i++) {
        for (int j = 0; j < plen/batch_size; j++) {
            results[i] = as_path_verify_upstream(aspa_table, &f[pos + j*batch_size], batch_size);
        }
        pos += plen*sizeof(uint32_t);
    }

    return results;
}

bool verify_as_path2(struct aspa_table *aspa_table, char* f)
{
    uint32_t plen = *(uint32_t*)f;
    size_t pos = sizeof(uint32_t);

    int count = 0;

    do {
        enum as_path_verification_result result = as_path_verify_upstream(aspa_table, (uint32_t*)&f[pos], plen);
        if (result != AS_PATH_VALID) {
            printf("%d %d %lu ", pos, plen, *(uint32_t*)(&f[pos]));
            for (uint32_t j = 0; j < plen; j++) {
                printf("%d -> ", *(uint32_t*)(&f[pos + j*sizeof(uint32_t)]));
            }
            printf("\n");
            return false;
        }
        pos += plen*sizeof(uint32_t);

        plen = *(uint32_t*)(&f[pos]);
        pos += sizeof(uint32_t);
        count++;
    } while (plen != 0);

    printf("%d ", count);

    return true;
}

bool verify_as_pathc(struct aspa_table *aspa_table)
{
    int count = 0;

    //uint32_t path[] = {174, 6461, 7018, 9002, 6939, 3356, 1299, 3257, 174};
    uint32_t path[] = {7018, 6461, 9002, 6939, 3356, 1299, 3257, 174};

    enum as_path_verification_result result = as_path_verify_upstream(aspa_table, path, 8);
    if (result != AS_PATH_VALID) {
        printf("custom path is invalid\n");
        return false;
    }

    return true;
}

bool verify_as_path3(struct aspa_table *aspa_table, char* fname)
{
    FILE *f = fopen(fname, "rb");
    assert(f != NULL);

    uint32_t plen;

    size_t readc = fread(&plen, sizeof(uint32_t), 1, f);
    assert(readc == 1);

    int count = 0;

    uint32_t* buffer = NULL;

    do {
            buffer = (uint32_t*)realloc(buffer, (size_t)(plen+1)*sizeof(uint32_t));
            readc = fread((char*)buffer, sizeof(uint32_t), plen+1, f);
            assert(readc == (plen+1) || readc == plen);

            enum as_path_verification_result result = as_path_verify_upstream(aspa_table, buffer, plen);
            if (result != AS_PATH_VALID) {
                printf("%d ", plen);
                for (uint32_t j = 0; j < plen; j++) {
                    printf("%d -> ", buffer[j]);
                }
                printf("\n");
                return false;
            }

            plen = readc == plen ? 0 : buffer[plen];

        count++;
    } while (plen != 0);

    printf("%d ", count);

    return true;
}

static struct aspa_table *load_aspa_table(struct aspa_table* aspa_table, struct rtr_socket* rtr_socket, char *f) {
    uint32_t len = *(uint32_t*)(&f[0]);
    long pos = sizeof(uint32_t);

    // struct aspa_array *vector;
    // assert(aspa_array_create(&vector) == 0);

    for (int i = len; i > 0; i--) {

        uint16_t pcount = *(uint32_t*)(&f[pos]);
        pos += sizeof(uint16_t);

        uint32_t cas = *(uint32_t*)(&f[pos]);
        pos += sizeof(uint32_t);

        struct aspa_record *record = (struct aspa_record *)lrtr_malloc(sizeof(struct aspa_record));
        record->customer_asn = cas;
        record->provider_count = pcount;

        // new_record->provider_asns = &f[pos];

        long size = pcount * sizeof(uint32_t);
        uint32_t *provider_asns = (uint32_t*)lrtr_malloc(size);
        memcpy(provider_asns, &f[pos], size);
        pos += size;
        record->provider_asns = provider_asns;

        assert(aspa_table_add(aspa_table, record, rtr_socket, false) == 0);
    }

    return ASPA_SUCCESS;
}

void run()
{
    struct aspa_table *aspa_table = (struct aspa_table*)lrtr_malloc(sizeof(struct aspa_table));
    aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

    clock_t c[6];

    #define D(a,b) ((double)(c[b]-c[a])/CLOCKS_PER_SEC)
    #define D(b) ((double)(c[b]-c[b-1])/CLOCKS_PER_SEC)

    c[0] = clock();
    char *f = buffer_file("/home/moritz/code/oss/rtrlib/algo/dumps/aspa2.dump");
    c[1] = clock();
	load_aspa_table(aspa_table, rtr_socket, f);
    c[2] = clock();

    printf("buffer %f parse %f ", D(1), D(2));

    char *w = buffer_file("/home/moritz/code/oss/rtrlib/algo/dumps/routes.dump");
    c[3] = clock();

    assert(verify_as_path2(aspa_table, w) == 1);
    c[4] = clock();

    for (int i = 0; i < 1600000; i++) {
        assert(verify_as_pathc(aspa_table) == 1);
    }
    c[5] = clock();


    printf("buffer %f verify %f verify_cystom %f\n",
        D(3), D(4), D(5));

}

int main() {
    run();
    return 0;
}

