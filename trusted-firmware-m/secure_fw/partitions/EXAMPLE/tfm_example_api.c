/*
 * Copyright (c) 2018-2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "psa/client.h"
#include "tfm_ns_interface.h"
#include "tfm_api.h"
#include "tfm_psa_call_param.h"
#include "tfm_veneers.h"
#ifdef TFM_PSA_API
#include "psa_manifest/sid.h"
#endif
/**** API functions ****/
psa_status_t rot_a_input_output(const void **in_data,
                        size_t in_data_count,
                        const void **out_data,
                        size_t out_data_count)
{
    psa_status_t status;
#ifdef TFM_PSA_API
    psa_handle_t handle;
#endif
    int16_t idx;
    psa_invec in_vecs[in_data_count];
    for(idx = 0 ; idx < in_data_count; idx++) {
        in_vecs[idx].base = in_data[idx];
        in_vecs[idx].len = sizeof(in_data[idx]);
    };
    psa_outvec out_vecs[out_data_count];
#ifdef TFM_PSA_API
    handle = psa_connect(ROT_A_INPUT_OUTPUT_SID, ROT_A_INPUT_OUTPUT_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, in_vecs, IOVEC_LEN(in_vecs),
                      out_vecs, IOVEC_LEN(out_vecs));

    psa_close(handle);

#else
status = tfm_rot_a_input_output_req_veneer(in_vecs, IOVEC_LEN(in_vecs), out_vecs, IOVEC_LEN(out_vecs));

    /* A parameter with a buffer pointer pointer that has data length longer
     * than maximum permitted is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     */
    if (status == (psa_status_t)TFM_ERROR_INVALID_PARAMETER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    return status;
}