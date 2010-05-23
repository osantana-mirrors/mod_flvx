/**
 *  Copyright 2006 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 *  Modified on 4.II.2008 by Artur Bodera (artur@bodera.com)
 *      - added offset reset if invalid
 *      - fixed content-length header generation
 *      - added last-modified header
 *      - inspiration: http://apachedev.ru/2006/07/13/mod_flvx-peredacha-potokovogo-flash-video
 *
 * Modified on 2010-05-23 by Marc Noirot (marc.noirot@gmail.com)
 *      - fixed FLVX_HEADER to be spec compliant
 *      - fixed a content-length that must take generated header into account
 *      - added a README file with build and configuration instructions
 *
 *  Usage:
 *      1. Compile and install with apxs tool:
 *          apxs -c -i ./mod_flvx.c
 *
 *           (http://httpd.apache.org/docs/2.0/programs/apxs.html)
 *
 *      2. Add the following lines to your httpd.conf or create a
 *         dedicated /etc/httpd/conf.d/mod_flvx.conf config file:
 *
 *         LoadModule flvx_module modules/mod_flvx.so
 *         AddHandler flv-stream .flv
 *
 *      3. Restart Apache!
 *
 *      4. Now your flv files can be streamed using ?start= parameter
 *
 */

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_buckets.h"
#include "apr_strings.h"

#define FLVX_HANDLER "flv-stream"

#define FLVX_HEADER "FLV\x1\x5\0\0\0\x9\0\0\0\0"
#define FLVX_HEADER_LEN (sizeof(FLVX_HEADER)-1)

static apr_off_t get_start(request_rec *r)
{
    apr_off_t start = 0;
    char *p = NULL;

    if (!r->args) {
        return start;
    }

    p = strstr(r->args, "start=");

    if (p) {
        p = p + 6;
        apr_strtoff(&start, p, NULL, 10);
    }

    return start;
}

static int drive_flvx(request_rec *r)
{
    apr_finfo_t fi;
    apr_bucket_brigade *bb;
    apr_off_t offset = 0;
    apr_off_t length = 0;
    apr_file_t *fp = NULL;
    apr_status_t rv = APR_SUCCESS;

    rv = apr_stat(&fi, r->filename, APR_FINFO_SIZE, r->pool);

    if (rv) {
        /* Let the core handle it. */
        return DECLINED;
    }

    /* Open the file */
    rv = apr_file_open(&fp, r->filename, APR_READ,
                       APR_OS_DEFAULT, r->pool);

    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "file permissions deny server access: %s", r->filename);
        return HTTP_FORBIDDEN;
    }

    offset = get_start(r);

    if (offset != 0 && offset < fi.size) {
        length = fi.size - offset;
    }
    else {
        length = fi.size;

        /* Offset should be reset if invalid            (mod by Artur Bodera (artur@bodera.com) */
        offset = 0;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if (offset != 0) {
        length += FLVX_HEADER_LEN;
        rv = apr_brigade_write(bb, NULL, NULL, FLVX_HEADER, FLVX_HEADER_LEN);
        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "unable to write flv header in brigade");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    apr_brigade_insert_file(bb, fp, offset, length, r->pool);

    ap_set_content_type(r, "video/x-flv");

    /* Content length should include FLV header         (mod by Artur Bodera (artur@bodera.com) */
    ap_set_content_length(r, length + FLVX_HEADER_LEN);

    /* Add last-modified headers                        (mod by Artur Bodera (artur@bodera.com) */
    ap_update_mtime(r, r->finfo.mtime);
    ap_set_last_modified(r);

    return ap_pass_brigade(r->output_filters, bb);
}

static int flvx_handler(request_rec *r)
{
    if ((!r->handler) ||
        (strcmp(r->handler, FLVX_HANDLER))) {
        return DECLINED;
    }

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    return drive_flvx(r);
}

static const command_rec flvx_cmds[] =
{
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(flvx_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA flvx_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    flvx_cmds,
    register_hooks
};

