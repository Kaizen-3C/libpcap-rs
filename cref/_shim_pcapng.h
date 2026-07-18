/* Minimal shim so libpcap 1.10.5's pcapng block-parser functions (read_bytes, read_block,
   get_from_block_data, get_opthdr_from_block_data, get_optvalue_from_block_data,
   process_idb_options, add_interface, pcap_ng_check_header, pcap_ng_cleanup,
   pcap_ng_next_packet) compile and run VERBATIM outside the full libpcap tree. It supplies the
   handful of types/constants/helpers those functions reference from pcap-int.h / pcap-common.c /
   pcap/pcap.h, plus a real (tmpfile-backed) FILE* so the verbatim `fread` calls work unchanged.
   The parser bodies themselves are sliced verbatim from src/sf-pcapng.c by cref/assemble.py —
   this shim is the ONLY added code. Mirrors the classic-pcap sf-pcap.c shim
   (upstream/libpcap-rs/cref/_shim.h) field-for-field; pcapng's pcap_t needs the same reduced
   surface (rfile/priv/swapped/version/linktype/snapshot/buffer/errbuf/next_packet_op/
   cleanup_op) plus linktype_ext. Helpers the parser calls out to (linktype_to_dlt,
   max_snaplen_for_dlt, pcapint_adjust_snapshot) are given their upstream-faithful behavior for
   the low-numbered DLTs the envelope uses. */
/* NOTE: this file is cref/_shim_pcapng.h, sliced together with sf-pcapng.c by
   cref/assemble_pcapng.py (the classic-pcap sibling is cref/_shim.h + cref/assemble.py). */
#ifndef LIBPCAP_PCAPNG_SHIM_H
#define LIBPCAP_PCAPNG_SHIM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

typedef uint32_t bpf_u_int32;
typedef int32_t  bpf_int32;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;

#define PCAP_ERRBUF_SIZE 256
#define MAXIMUM_SNAPLEN 262144

#define PCAP_TSTAMP_PRECISION_MICRO 0
#define PCAP_TSTAMP_PRECISION_NANO  1

#define SWAPLONG(y) \
    ((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#define SWAPSHORT(y) \
    ((((y)&0xff)<<8) | (((y)&0xff00)>>8))
#define SWAPLL(ull)  (((ull & 0xff00000000000000ULL) >> 56) | \
                      ((ull & 0x00ff000000000000ULL) >> 40) | \
                      ((ull & 0x0000ff0000000000ULL) >> 24) | \
                      ((ull & 0x000000ff00000000ULL) >> 8)  | \
                      ((ull & 0x00000000ff000000ULL) << 8)  | \
                      ((ull & 0x0000000000ff0000ULL) << 24) | \
                      ((ull & 0x000000000000ff00ULL) << 40) | \
                      ((ull & 0x00000000000000ffULL) << 56))
/* link types handled by the post-process cluster (values verbatim from pcap/dlt.h) */
#define DLT_LINUX_SLL          113
#define DLT_PFLOG              117
#define DLT_USB_LINUX          189
#define DLT_USB_LINUX_MMAPPED  220
#define DLT_NFLOG             239
#define DLT_LINUX_SLL2        276
/* big-endian 2-byte accessor: upstream extract.h's EXTRACT_BE_U_2, in portable byte form */
static inline uint16_t EXTRACT_BE_U_2(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

struct pcap_pkthdr {
    struct timeval_shim { long tv_sec, tv_usec; } ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

/* forward decl of the reduced pcap_t (fields the pcapng functions touch) */
struct pcap;
typedef struct pcap pcap_t;
typedef int  (*next_packet_op_t)(pcap_t *, struct pcap_pkthdr *, u_char **);
typedef void (*cleanup_op_t)(pcap_t *);

struct pcap {
    FILE *rfile;
    void *priv;
    int swapped;
    int version_major, version_minor;
    bpf_u_int32 linktype;
    bpf_u_int32 linktype_ext;
    int snapshot;
    u_char *buffer;
    u_int bufsize;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct { u_int tstamp_precision; } opt;
    next_packet_op_t next_packet_op;
    cleanup_op_t cleanup_op;
};

/* PCAP_OPEN_OFFLINE_COMMON expands to a call to this; allocate pcap_t + private area */
static pcap_t *pcapint_open_offline_common(char *ebuf, size_t total_size, size_t private_data) {
    (void)ebuf;
    char *block = (char *)calloc(1, total_size);
    if (!block) return NULL;
    pcap_t *p = (pcap_t *)block;
    p->priv = block + private_data;
    return p;
}
#define PCAP_OPEN_OFFLINE_COMMON(ebuf, type) \
    pcapint_open_offline_common(ebuf, \
        sizeof(struct { pcap_t __common; type __private; }), \
        offsetof(struct { pcap_t __common; type __private; }, __private))

static bpf_u_int32 pcapint_adjust_snapshot(bpf_u_int32 linktype, bpf_u_int32 snaplen) {
    (void)linktype;
    if (snaplen == 0 || snaplen > MAXIMUM_SNAPLEN)
        return MAXIMUM_SNAPLEN;
    return snaplen;
}

static int linktype_to_dlt(int linktype) { return linktype; }         /* identity for low DLTs */
static bpf_u_int32 max_snaplen_for_dlt(int dlt) { (void)dlt; return MAXIMUM_SNAPLEN; }

static void pcapint_fmt_errmsg_for_errno(char *errbuf, size_t size, int errnum, const char *fmt, ...) {
    (void)errnum;
    if (size) snprintf(errbuf, size, "%s", fmt);   /* text stable; errno branch unused in-memory */
}

static void pcapint_sf_cleanup(pcap_t *p) {
    if (p->buffer) free(p->buffer);
    if (p->rfile) fclose(p->rfile);
}

/* pcapint_post_process + swap_pseudo_headers + the per-DLT swap helpers are sliced VERBATIM
   from pcap-util.c by assemble_pcapng.py and appended right after this shim (with the
   pseudo-header structs sliced verbatim from the pcap headers), so the pcapng differential now
   actually exercises post-processing instead of hiding it behind a no-op. See assemble_pcapng.py. */

#endif
