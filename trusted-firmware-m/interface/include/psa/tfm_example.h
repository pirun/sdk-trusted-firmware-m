/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/client.h"
#include "tfm_ns_interface.h"
#include "tfm_api.h"
#include "tfm_psa_call_param.h"
#include "tfm_veneers.h"
#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
/**** API functions ****/
psa_status_t rot_a_input_output(const void **in_data,
                        size_t in_data_count,
                        const void **out_data,
                        size_t out_data_count);

psa_status_t rot_b_crypto_hash(const void *in_data,
                        const void *out_data);

psa_status_t rot_c_crypto_rand(const void *out_data);