/* Op-script driver over the VERBATIM libpcap savefile-parser functions (sliced above by
   assemble.py). Each stdin line is a whole classic-pcap file as hex. The driver backs a real
   FILE* with a tmpfile (so the verbatim `fread` calls run unchanged), replays the exact caller
   sequence libpcap uses (read the 4-byte magic, then pcap_check_header, then the
   next_packet_op loop), and prints a deterministic trace:
     H <vmaj> <vmin> <swapped> <linktype> <snapshot>   file header accepted
     X <errbuf-or-"not-pcap">                           header rejected (verbatim diagnostic)
     P <caplen> <len> <sec> <usec> <fnv>                packet accepted (FNV-1a of captured bytes)
     E <errbuf>                                         packet rejected (verbatim diagnostic)
     Z <n>                                              clean EOF after n packets
   Every line ends with a "." separator. The Rust port must reproduce stdout exactly, including
   the verbatim error-message text. */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char inbuf[1 << 20];

int main(void) {
    static char line[2 * (1 << 20) + 4];
    while (fgets(line, sizeof line, stdin)) {
        long n = 0, i;
        for (i = 0; line[2*i] && line[2*i+1]; i++) {
            int hi = hexval((unsigned char)line[2*i]);
            int lo = hexval((unsigned char)line[2*i+1]);
            if (hi < 0 || lo < 0) break;
            if (n >= (long)sizeof(inbuf)) break;
            inbuf[n++] = (unsigned char)((hi << 4) | lo);
        }

        FILE *fp = tmpfile();
        if (!fp) { printf("X tmpfile-failed\n.\n"); continue; }
        if (n > 0) fwrite(inbuf, 1, (size_t)n, fp);
        rewind(fp);

        uint8_t magic[4];
        if (fread(magic, 1, 4, fp) != 4) { printf("X not-pcap\n.\n"); fclose(fp); continue; }

        int err = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        errbuf[0] = '\0';
        pcap_t *p = pcap_check_header(magic, fp, PCAP_TSTAMP_PRECISION_MICRO, errbuf, &err);
        if (!p) {
            printf("X %s\n.\n", errbuf[0] ? errbuf : "not-pcap");
            fclose(fp);
            continue;
        }
        /* upstream's pcap_fopen_offline sets p->rfile = fp after check_header returns */
        p->rfile = fp;
        printf("H %d %d %d %u %d\n", p->version_major, p->version_minor, p->swapped,
               p->linktype, p->snapshot);

        int npkt = 0;
        for (;;) {
            struct pcap_pkthdr hdr;
            u_char *data = NULL;
            memset(&hdr, 0, sizeof hdr);
            int rc = p->next_packet_op(p, &hdr, &data);
            if (rc == 0) break;
            if (rc < 0) { printf("E %s\n", p->errbuf); break; }
            unsigned long h = 2166136261UL;
            bpf_u_int32 k;
            for (k = 0; k < hdr.caplen; k++) { h ^= data[k]; h = (h * 16777619UL) & 0xffffffffUL; }
            printf("P %u %u %ld %ld %08lx\n", hdr.caplen, hdr.len,
                   hdr.ts.tv_sec, hdr.ts.tv_usec, h & 0xffffffffUL);
            npkt++;
        }
        printf("Z %d\n.\n", npkt);

        p->cleanup_op(p);
        free(p);
    }
    return 0;
}
