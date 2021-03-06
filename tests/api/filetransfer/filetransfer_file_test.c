/*
 * Copyright (c) 2018 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>

#include <CUnit/Basic.h>
#include <vlog.h>

#include "ela_carrier.h"
#include "ela_filetransfer.h"

#include "config.h"
#include "cond.h"
#include "test_helper.h"

static inline void wakeup(void* context)
{
    cond_signal(((CarrierContext *)context)->cond);
}

static void ready_cb(ElaCarrier *w, void *context)
{
    cond_signal(((CarrierContext *)context)->ready_cond);
}

static void friend_added_cb(ElaCarrier *w, const ElaFriendInfo *info, void *context)
{
    wakeup(context);
}

static void friend_connection_cb(ElaCarrier *w, const char *friendid,
                                 ElaConnectionStatus status, void *context)
{
    CarrierContext *wctxt = (CarrierContext *)context;

    wctxt->friend_status = (status == ElaConnectionStatus_Connected) ?
                         ONLINE : OFFLINE;
    cond_signal(wctxt->friend_status_cond);

    vlogD("Robot connection status changed -> %s", connection_str(status));
}

static ElaCallbacks callbacks = {
    .idle            = NULL,
    .connection_status = NULL,
    .ready           = ready_cb,
    .self_info       = NULL,
    .friend_list     = NULL,
    .friend_connection = friend_connection_cb,
    .friend_info     = NULL,
    .friend_presence = NULL,
    .friend_request  = NULL,
    .friend_added    = friend_added_cb,
    .friend_removed  = NULL,
    .friend_message  = NULL,
    .friend_invite   = NULL
};

static void ft_state_changed_cb(FileTransferConnection state, void *context)
{
    TestContext *wtxt = (TestContext*)context;
    CarrierContext *ctx = wtxt->carrier;

    ctx->ft_con_state = state;
    ctx->ft_con_state_bits |= (1 << state);
    cond_signal(ctx->ft_cond);
}

static void sent_cb(size_t length, uint64_t totalsz, void *context)
{
    TestContext *wtxt = (TestContext*)context;
    CarrierContext *ctx = wtxt->carrier;

    if (length == totalsz)
        cond_signal(ctx->ft_cond);
}

static ElaFileProgressCallbacks fp_calllbacks = {
    .state_changed = ft_state_changed_cb,
    .sent = sent_cb,
    .received = NULL
};

struct CarrierContextExtra {
    char file_name[ELA_MAX_FILE_NAME_LEN + 1];
};

static CarrierContextExtra extra = {
    .file_name = {"test-file-name"}
};

static Condition DEFINE_COND(ready_cond);
static Condition DEFINE_COND(cond);
static Condition DEFINE_COND(friend_status_cond);
static Condition DEFINE_COND(ft_cond);

static CarrierContext carrier_context = {
    .cbs = &callbacks,
    .carrier = NULL,
    .ft = NULL,
    .ft_info = NULL,
    .ft_cbs = NULL,
    .ft_cond = &ft_cond,
    .ready_cond = &ready_cond,
    .cond = &cond,
    .friend_status_cond = &friend_status_cond,
    .extra = &extra
};

static void test_context_reset(TestContext *context)
{
    cond_reset(context->carrier->cond);
    cond_reset(context->carrier->friend_status_cond);
    cond_reset(context->carrier->ft_cond);
    context->carrier->ft_con_state_bits = 0;
}

static TestContext test_context = {
    .carrier = &carrier_context,
    .session = NULL,
    .stream  = NULL,
    .context_reset = test_context_reset
};

static void test_filetransfer_file(void)
{
    CarrierContext *wctxt = test_context.carrier;
    CarrierContextExtra *extra = wctxt->extra;
    char userid[ELA_MAX_ID_LEN + 1] = {0};
    char cmd[32] = {0};
    char result[32] = {0};
    char *p;
    const char *data = "hello";
    uint8_t ft_con_state_bits = 0;
    int rc;

    test_context.context_reset(&test_context);

    rc = add_friend_anyway(&test_context, robotid, robotaddr);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_TRUE_FATAL(ela_is_friend(wctxt->carrier, robotid));

    // Create a file to transfer.
    sprintf(result, "printf %s > %s", data, extra->file_name);
    rc = system(result);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    rc = ela_filetransfer_init(wctxt->carrier, NULL, &test_context);
    CU_ASSERT_EQUAL(rc, 0);

    rc = write_cmd("ft_init\n");
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_init") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "succeeded") == 0);

    rc = ela_file_send(wctxt->carrier, robotid, extra->file_name, &fp_calllbacks, &test_context);
    CU_ASSERT_EQUAL(rc, 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_connect") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "received") == 0);

    ela_get_userid(wctxt->carrier, userid, sizeof(userid));
    rc = write_cmd("ft_recv %s\n", userid);
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_recv") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "succeeded") == 0);

    /* Wait for the ft_state_changed_cb to be invoked. After invocation,
       the filetransfer connection state should have changed to be
       FileTransferConnection_connecting. */
    cond_wait(wctxt->ft_cond);

    /* Wait for the ft_state_changed_cb to be invoked. After invocation,
       the filetransfer connection state should have changed to be
       FileTransferConnection_connected. */
    cond_wait(wctxt->ft_cond);

    ft_con_state_bits |= 1 << FileTransferConnection_connecting;
    ft_con_state_bits |= 1 << FileTransferConnection_connected;
    CU_ASSERT_EQUAL_FATAL(wctxt->ft_con_state_bits, ft_con_state_bits);

    // Wait for the sent_cb to be invoked.
    cond_wait(wctxt->ft_cond);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "fp_recv") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "done") == 0);

    rc = write_cmd("ft_res\n");
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_res") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, data) == 0);

    ela_filetransfer_cleanup(wctxt->carrier);

    // Delete the file created before.
    rc = remove(extra->file_name);
    CU_ASSERT_EQUAL(rc, 0);
}

static void test_filetransfer_file_resume_interrupted_transferring(void)
{
    CarrierContext *wctxt = test_context.carrier;
    CarrierContextExtra *extra = wctxt->extra;
    char userid[ELA_MAX_ID_LEN + 1] = {0};
    char cmd[32] = {0};
    char result[32] = {0};
    char *p;
    const char *data = "abcd";
    uint8_t ft_con_state_bits = 0;
    int rc;

    test_context.context_reset(&test_context);

    rc = add_friend_anyway(&test_context, robotid, robotaddr);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_TRUE_FATAL(ela_is_friend(wctxt->carrier, robotid));

    // Create a file to transfer.
    sprintf(result, "printf %s > %s", data, extra->file_name);
    rc = system(result);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    rc = ela_filetransfer_init(wctxt->carrier, NULL, &test_context);
    CU_ASSERT_EQUAL(rc, 0);

    rc = write_cmd("ft_init\n");
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_init") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "succeeded") == 0);

    rc = ela_file_send(wctxt->carrier, robotid, extra->file_name, &fp_calllbacks, &test_context);
    CU_ASSERT_EQUAL(rc, 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_connect") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "received") == 0);

    ela_get_userid(wctxt->carrier, userid, sizeof(userid));
    rc = write_cmd("ft_recv %s %s\n", userid, "ab");
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_recv") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "succeeded") == 0);

    /* Wait for the ft_state_changed_cb to be invoked. After invocation,
       the filetransfer connection state should have changed to be
       FileTransferConnection_connecting. */
    cond_wait(wctxt->ft_cond);

    /* Wait for the ft_state_changed_cb to be invoked. After invocation,
       the filetransfer connection state should have changed to be
       FileTransferConnection_connected. */
    cond_wait(wctxt->ft_cond);

    ft_con_state_bits |= 1 << FileTransferConnection_connecting;
    ft_con_state_bits |= 1 << FileTransferConnection_connected;
    CU_ASSERT_EQUAL_FATAL(wctxt->ft_con_state_bits, ft_con_state_bits);

    // Wait for the sent_cb to be invoked.
    cond_wait(wctxt->ft_cond);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "fp_recv") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, "done") == 0);

    rc = write_cmd("ft_res\n");
    CU_ASSERT_FATAL(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    CU_ASSERT_TRUE_FATAL(rc == 2);
    CU_ASSERT_TRUE_FATAL(strcmp(cmd, "ft_res") == 0);
    CU_ASSERT_TRUE_FATAL(strcmp(result, data) == 0);

    ela_filetransfer_cleanup(wctxt->carrier);

    // Delete the file created before.
    rc = remove(extra->file_name);
    CU_ASSERT_EQUAL(rc, 0);
}

static CU_TestInfo cases[] = {
    { "test_filetransfer_file", test_filetransfer_file },
    { "test_filetransfer_file_resume_interrupted_transferring", test_filetransfer_file_resume_interrupted_transferring },
    { NULL, NULL }
};

CU_TestInfo *filetransfer_file_test_get_cases(void)
{
    return cases;
}

int filetransfer_file_test_suite_init(void)
{
    int rc;

    rc = test_suite_init(&test_context);
    if (rc < 0)
        CU_FAIL("Error: test suite initialize error");

    return rc;
}

int filetransfer_file_test_suite_cleanup(void)
{
    test_suite_cleanup(&test_context);
    return 0;
}
