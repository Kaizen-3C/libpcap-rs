/* In-process callable wrapper over the VERBATIM libpcap savefile-parser functions (sliced by
   assemble_fuzzlib.py), for differential fuzzing. Same op-script logic as _driver.c — same
   trace grammar, same field-by-field formatting — just returning the trace via a caller-owned
   buffer (open_memstream) instead of printing it, and taking raw bytes directly instead of a
   hex-decoded stdin line (the fuzzer already hands us raw bytes). Any behavioral difference
   from _driver.c here would invalidate the differential-fuzz oracle, so keep this in lockstep
   with _driver.c's per-case body. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Runs one case; *outlen receives the trace length. Returns a malloc'd buffer the caller must
   free with free_case_c(); returns NULL only on the (unrecoverable) tmpfile-creation failure. */
char *run_case_c(const uint8_t *filedata, size_t n, size_t *outlen) {
    char *buf = NULL;
    size_t bufsz = 0;
    FILE *out = open_memstream(&buf, &bufsz);
    if (!out) {
        *outlen = 0;
        return NULL;
    }

    if (n < 4) {
        fprintf(out, "X not-pcap\n.\n");
        fclose(out);
        *outlen = bufsz;
        return buf;
    }

    FILE *fp = tmpfile();
    if (!fp) {
        fprintf(out, "X tmpfile-failed\n.\n");
        fclose(out);
        *outlen = bufsz;
        return buf;
    }
    if (n > 4)
        fwrite(filedata + 4, 1, n - 4, fp);
    rewind(fp);

    uint8_t magic[4];
    memcpy(magic, filedata, 4);

    int err = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';
    pcap_t *p = pcap_check_header(magic, fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf, &err);
    if (!p) {
        fprintf(out, "X %s\n.\n", errbuf[0] ? errbuf : "not-pcap");
        fclose(fp);
        fclose(out);
        *outlen = bufsz;
        return buf;
    }
    /* upstream's pcap_fopen_offline sets p->rfile = fp after check_header returns */
    p->rfile = fp;
    fprintf(out, "H %d %d %d %u %d\n", p->version_major, p->version_minor, p->swapped,
            p->linktype, p->snapshot);

    int npkt = 0;
    for (;;) {
        struct pcap_pkthdr hdr;
        u_char *data = NULL;
        memset(&hdr, 0, sizeof hdr);
        int rc = p->next_packet_op(p, &hdr, &data);
        if (rc == 0)
            break;
        if (rc < 0) {
            fprintf(out, "E %s\n", p->errbuf);
            break;
        }
        unsigned long h = 2166136261UL;
        bpf_u_int32 k;
        for (k = 0; k < hdr.caplen; k++) {
            h ^= data[k];
            h = (h * 16777619UL) & 0xffffffffUL;
        }
        fprintf(out, "P %u %u %ld %ld %08lx\n", hdr.caplen, hdr.len, hdr.ts.tv_sec,
                hdr.ts.tv_usec, h & 0xffffffffUL);
        npkt++;
    }
    fprintf(out, "Z %d\n.\n", npkt);

    p->cleanup_op(p);
    free(p);
    fclose(out);
    *outlen = bufsz;
    return buf;
}

void free_case_c(char *p) {
    free(p);
}
