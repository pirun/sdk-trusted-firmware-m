/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "platform_sp.h"

#include "tfm_platform_system.h"
#include "tfm/tfm_spm_services.h"
#include "tfm_secure_api.h"
#include "psa_manifest/pid.h"

#ifndef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
#include "tfm_plat_nv_counters.h"
#define NV_COUNTER_ID_SIZE  sizeof(enum tfm_nv_counter_t)
#define NV_COUNTER_MAP_SIZE   3

/* Access map using NVCOUNTER_IDX -> tfm_partition-id key-value pairs */
static const int32_t nv_counter_access_map[NV_COUNTER_MAP_SIZE] = {
                                          [PLAT_NV_COUNTER_0] = TFM_SP_PS,
                                          [PLAT_NV_COUNTER_1] = TFM_SP_PS,
                                          [PLAT_NV_COUNTER_2] = TFM_SP_PS
              };
#endif /* TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED */

#ifdef TFM_PSA_API
#include "psa_manifest/tfm_platform.h"
#include "psa/client.h"
#include "psa/service.h"
#include "region_defs.h"

#define INPUT_BUFFER_SIZE  64
#define OUTPUT_BUFFER_SIZE 64

typedef enum tfm_platform_err_t (*plat_func_t)(const psa_msg_t *msg);
#endif

#ifndef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
/*
 * \brief Verifies ownership of a nv_counter resource to a partition id.
 *
 * \param[in] nv_counter_no  Number of nv_counter as assigned in platform.
 *
 * \return true if the calling partition is allowed to access this counter id
 */

static bool nv_counter_access_grant(int32_t client_id,
                                    enum tfm_nv_counter_t nv_counter_no)
{
    int32_t req_id;

    /* Boundary check the input argument */
    if (nv_counter_no >= NV_COUNTER_MAP_SIZE ||
        (int32_t)nv_counter_no < 0 || nv_counter_no >= PLAT_NV_COUNTER_MAX) {
        return false;
    }

    req_id = nv_counter_access_map[nv_counter_no];

    /* NV Counters are indexed from 0 and incremented. A gap in the platform
     *  counter sequence is assigned a zero( invalid ) partition id
     */
    if (client_id == req_id && req_id != 0) {
       return true;
    }
    return false;
}
#endif /* TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED */

enum tfm_platform_err_t platform_sp_system_reset(void)
{
    /* Check if SPM allows the system reset */

    if (tfm_spm_request_reset_vote() != 0) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    /* FIXME: The system reset functionality is only supported in isolation
     *        level 1.
     */

    tfm_platform_hal_system_reset();

    return TFM_PLATFORM_ERR_SUCCESS;
}

#ifndef TFM_PSA_API

enum tfm_platform_err_t
platform_sp_ioctl(psa_invec  *in_vec,  uint32_t num_invec,
                  psa_outvec *out_vec, uint32_t num_outvec)
{
    void *input, *output;
    tfm_platform_ioctl_req_t request;

    if ((num_invec < 1) || (num_invec > 2) ||
        (num_outvec > 1) ||
        (in_vec[0].base == NULL) ||
        (in_vec[0].len != sizeof(tfm_platform_ioctl_req_t))) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    input = (num_invec == 1) ? NULL : &in_vec[1];
    output = out_vec;
    request = *((tfm_platform_ioctl_req_t *)in_vec[0].base);

    return tfm_platform_hal_ioctl(request, input, output);
}

enum tfm_platform_err_t
platform_sp_nv_counter_read(psa_invec  *in_vec,  uint32_t num_invec,
                            psa_outvec *out_vec, uint32_t num_outvec)
{
#ifdef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    enum tfm_plat_err_t err;
    enum tfm_nv_counter_t counter_id;
    uint32_t counter_size;
    int32_t status, client_id;

    if (in_vec[0].len != NV_COUNTER_ID_SIZE ||
        num_invec != 1 || num_outvec != 1) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }
    counter_id = *((enum tfm_nv_counter_t *)in_vec[0].base);
    counter_size = out_vec[0].len;

    status = tfm_core_get_caller_client_id(&client_id);
    if (status != (int32_t)TFM_SUCCESS) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    if (!nv_counter_access_grant(client_id, counter_id)) {
       return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }
    err = tfm_plat_read_nv_counter(counter_id, counter_size,
                                   (uint8_t *)out_vec[0].base);
    if (err != TFM_PLAT_ERR_SUCCESS) {
       return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    return TFM_PLATFORM_ERR_SUCCESS;
#endif /* TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED */
}

enum tfm_platform_err_t
platform_sp_nv_counter_increment(psa_invec  *in_vec,  uint32_t num_invec,
                                 psa_outvec *out_vec, uint32_t num_outvec)
{
#ifdef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    enum tfm_plat_err_t err;
    enum tfm_nv_counter_t counter_id;
    int32_t client_id, status;

    if (in_vec[0].len != NV_COUNTER_ID_SIZE ||
        num_invec != 1 || num_outvec != 0) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    status = tfm_core_get_caller_client_id(&client_id);
    if (status != (int32_t)TFM_SUCCESS) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    counter_id = *((enum tfm_nv_counter_t *)in_vec[0].base);

    if (!nv_counter_access_grant(client_id, counter_id)) {
       return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }
    err = tfm_plat_increment_nv_counter(counter_id);
    if (err != TFM_PLAT_ERR_SUCCESS) {
       return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    return TFM_PLATFORM_ERR_SUCCESS;
#endif /* TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED */
}

#else /* TFM_PSA_API */

static enum tfm_platform_err_t
platform_sp_system_reset_ipc(const psa_msg_t *msg)
{
    (void)msg; /* unused parameter */

    return platform_sp_system_reset();
}

static enum tfm_platform_err_t
platform_sp_nv_counter_ipc(const psa_msg_t *msg)
{
#ifdef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    enum tfm_plat_err_t err = TFM_PLAT_ERR_SYSTEM_ERR;
    size_t in_len = PSA_MAX_IOVEC, out_len = PSA_MAX_IOVEC, num = 0;

    enum tfm_nv_counter_t counter_id;
    uint8_t counter_val = 0;

    /* Check the number of in_vec filled */
    while ((in_len > 0) && (msg->in_size[in_len - 1] == 0)) {
        in_len--;
    }

    /* Check the number of out_vec filled */
    while ((out_len > 0) && (msg->out_size[out_len - 1] == 0)) {
        out_len--;
    }
    switch (msg->type) {
    case TFM_PLATFORM_API_ID_NV_INCREMENT:
        if (msg->in_size[0] != NV_COUNTER_ID_SIZE ||
            in_len != 1 || out_len != 0) {
            return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }

        num = psa_read(msg->handle, 0, &counter_id, msg->in_size[0]);

        if (num != msg->in_size[0]) {
            return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }

        if (!nv_counter_access_grant(msg->client_id, counter_id)) {
           return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }

        err = tfm_plat_increment_nv_counter(counter_id);
        break;
    case TFM_PLATFORM_API_ID_NV_READ:
        num = psa_read(msg->handle, 0, &counter_id, msg->in_size[0]);

        if (msg->in_size[0] != NV_COUNTER_ID_SIZE ||
            in_len != 1 || out_len != 1) {
            return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }

        if (!nv_counter_access_grant(msg->client_id, counter_id)) {
           return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }

        err = tfm_plat_read_nv_counter(counter_id,  msg->out_size[0],
                                       &counter_val);

        if (err != TFM_PLAT_ERR_SUCCESS) {
           return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        }
        psa_write(msg->handle, 0, &counter_val, msg->out_size[0]);
        break;
    default:
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
        break;
    }

    if (err != TFM_PLAT_ERR_SUCCESS) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }
    return TFM_PLATFORM_ERR_SUCCESS;
#endif /* TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED */
}

static enum tfm_platform_err_t
platform_sp_ioctl_ipc(const psa_msg_t *msg)
{
    void *input = NULL;
    void *output = NULL;
    psa_invec invec = {0};
    psa_outvec outvec = {0};
    uint8_t input_buffer[INPUT_BUFFER_SIZE] = {0};
    uint8_t output_buffer[OUTPUT_BUFFER_SIZE] = {0};
    tfm_platform_ioctl_req_t request = 0;
    enum tfm_platform_err_t ret = TFM_PLATFORM_ERR_SYSTEM_ERROR;
    int num = 0;
    uint32_t in_len = PSA_MAX_IOVEC;
    uint32_t out_len = PSA_MAX_IOVEC;

    while ((in_len > 0) && (msg->in_size[in_len - 1] == 0)) {
        in_len--;
    }

    while ((out_len > 0) && (msg->out_size[out_len - 1] == 0)) {
        out_len--;
    }

    if ((in_len < 1) || (in_len > 2) ||
        (out_len > 1)) {
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
    }

    num = psa_read(msg->handle, 0, &request, sizeof(request));
    if (num != sizeof(request)) {
        return (enum tfm_platform_err_t) PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (in_len > 1) {
        if (msg->in_size[1] > INPUT_BUFFER_SIZE) {
            return (enum tfm_platform_err_t) PSA_ERROR_PROGRAMMER_ERROR;
        }
        num = psa_read(msg->handle, 1, &input_buffer, msg->in_size[1]);
        if (num != msg->in_size[1]) {
            return (enum tfm_platform_err_t) PSA_ERROR_PROGRAMMER_ERROR;
        }
        invec.base = input_buffer;
        invec.len = msg->in_size[1];
        input = &invec;
    }

    if (out_len > 0) {
        if (msg->out_size[0] > OUTPUT_BUFFER_SIZE) {
            return (enum tfm_platform_err_t) PSA_ERROR_PROGRAMMER_ERROR;
        }
        outvec.base = output_buffer;
        outvec.len = msg->out_size[0];
        output = &outvec;
    }

    ret = tfm_platform_hal_ioctl(request, input, output);

    if (output != NULL) {
        psa_write(msg->handle, 0, outvec.base, outvec.len);
    }

    return ret;
}

static void platform_signal_handle(psa_signal_t signal, plat_func_t pfn)
{
    psa_msg_t msg;
    psa_status_t status;

    status = psa_get(signal, &msg);
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    case PSA_IPC_CALL:
    case TFM_PLATFORM_API_ID_NV_READ:
    case TFM_PLATFORM_API_ID_NV_INCREMENT:
        status = (psa_status_t)pfn(&msg);
        psa_reply(msg.handle, status);
        break;
    case PSA_IPC_DISCONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
    }
}

#endif /* TFM_PSA_API */

enum tfm_platform_err_t platform_sp_init(void)
{
#ifndef TFM_PLATFORM_NV_COUNTER_MODULE_DISABLED
    /* Initialise the non-volatile counters */
    enum tfm_plat_err_t err;
    err = tfm_plat_init_nv_counter();
    if (err != TFM_PLAT_ERR_SUCCESS) {
#ifdef TFM_PSA_API
        psa_panic();
#else
        return TFM_PLATFORM_ERR_SYSTEM_ERROR;
#endif
    }
#endif /* TFM_PLATFORM_MODULE_NV_COUNTER_DISABELD */

#ifdef TFM_PSA_API
    psa_signal_t signals = 0;

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & TFM_SP_PLATFORM_SYSTEM_RESET_SIGNAL) {
            platform_signal_handle(TFM_SP_PLATFORM_SYSTEM_RESET_SIGNAL,
                                   platform_sp_system_reset_ipc);
        } else if (signals & TFM_SP_PLATFORM_IOCTL_SIGNAL) {
            platform_signal_handle(TFM_SP_PLATFORM_IOCTL_SIGNAL,
                                   platform_sp_ioctl_ipc);
       } else if (signals & TFM_SP_PLATFORM_NV_COUNTER_SIGNAL) {
            platform_signal_handle(TFM_SP_PLATFORM_NV_COUNTER_SIGNAL,
                                   platform_sp_nv_counter_ipc);
        } else {
            psa_panic();
        }
    }

#else
    return TFM_PLATFORM_ERR_SUCCESS;
#endif /* TFM_PSA_API */
}
