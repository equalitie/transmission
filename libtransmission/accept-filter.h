/*
 * This file Copyright (C) Transmission authors and contributors
 *
 * It may be used under the 3-Clause BSD License, the GNU Public License v2,
 * or v3, or any future license endorsed by Mnemosyne LLC.
 *
 */

/*
 * This file defines the public API for the libtransmission library.
 * The other public API headers are variant.h and utils.h;
 * most of the remaining headers in libtransmission are private.
 */

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

struct tr_peerIo;

typedef enum
{
    FILTER_PASS,
    FILTER_LATER,
    FILTER_FAIL
}
FilterState;

typedef FilterState (* handshakeFilter)(const unsigned char* data, size_t);
typedef void (* filterCallback)(struct tr_peerIo*, void* userdata);

struct tr_accept_filter {
    handshakeFilter filter;
    filterCallback  callback;
    void* userdata;
};

#ifdef __cplusplus
}
#endif

