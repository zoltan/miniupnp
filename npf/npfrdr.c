#include "../upnpglobalvars.h"


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <sys/cdefs.h>
#include <inttypes.h>
#include <err.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/npf_ncode.h>
#include <net/npf.h>
#include <npf.h>

#define NC_ALLOC_MASK           (64 - 1)
#define NC_ALLOC_ROUND(x)       (((x) + NC_ALLOC_MASK) & ~NC_ALLOC_MASK)

#define NC_MATCH_DST            0x01
#define NC_MATCH_SRC            0x02

#define NC_MATCH_TCP            0x04
#define NC_MATCH_UDP            0x08
#define NC_MATCH_ICMP           0x10
#define NC_MATCH_ICMP6          0x20


struct nc_ctx {
        void *                  nc_buf;
        void *                  nc_iptr;
        size_t                  nc_len;
        size_t                  nc_expected;
        ptrdiff_t *             nc_jmp_list;
        size_t                  nc_jmp_len;
        size_t                  nc_jmp_it;
        size_t                  nc_saved_it;
};

typedef struct nc_ctx nc_ctx_t;

static uint32_t *npfctl_ncgen_getptr(nc_ctx_t *ctx, size_t nwords)
{
        size_t offset, reqlen;

        ctx->nc_expected = (sizeof(uint32_t) * nwords);

        offset = (uintptr_t)ctx->nc_iptr - (uintptr_t)ctx->nc_buf;
        reqlen = offset + ctx->nc_expected;
        if (reqlen < ctx->nc_len) {
                return ctx->nc_iptr;
        }

        ctx->nc_len = NC_ALLOC_ROUND(reqlen);
        ctx->nc_buf = realloc(ctx->nc_buf, ctx->nc_len);
        ctx->nc_iptr = (uint8_t *)ctx->nc_buf + offset;
        return ctx->nc_iptr;
}


static void
npfctl_ncgen_putptr(nc_ctx_t *ctx, void *nc)
{
        ptrdiff_t diff = (uintptr_t)nc - (uintptr_t)ctx->nc_iptr;

        if ((ptrdiff_t)ctx->nc_expected != diff) {
                errx(EXIT_FAILURE, "unexpected n-code fragment size "
                    "(expected words %zu, diff %td)", ctx->nc_expected, diff);
        }
        ctx->nc_expected = 0;
        ctx->nc_iptr = nc;

}

static void
npfctl_ncgen_addjmp(nc_ctx_t *ctx, uint32_t **nc_ptr)
{
        printf("addjmp\n");
        size_t reqlen, i = ctx->nc_jmp_it++;
        uint32_t *nc = *nc_ptr;

        reqlen = NC_ALLOC_ROUND(ctx->nc_jmp_it * sizeof(ptrdiff_t));

        if (reqlen > NC_ALLOC_ROUND(ctx->nc_jmp_len)) {
                ctx->nc_jmp_list = realloc(ctx->nc_jmp_list, reqlen);
                ctx->nc_jmp_len = reqlen;
        }

        ctx->nc_jmp_list[i] = (uintptr_t)nc - (uintptr_t)ctx->nc_buf;

        *nc++ = NPF_OPCODE_BNE;
        *nc++ = 0xdeadbeef;
        *nc_ptr = nc;
}

static void *
zalloc (size_t size)
{
    void *p = malloc (size);
    memset (p, 0, size);
    return p;
}

nc_ctx_t *
npfctl_ncgen_create(void)
{
        return zalloc(sizeof(nc_ctx_t));
}
void *
npfctl_ncgen_complete(nc_ctx_t *ctx, size_t *sz)
{
        uint32_t *nc = npfctl_ncgen_getptr(ctx, 4);
        ptrdiff_t foff;
        size_t i;


        *nc++ = NPF_OPCODE_RET;
        *nc++ = 0x0;

        foff = ((uintptr_t)nc - (uintptr_t)ctx->nc_buf) / sizeof(uint32_t);
        *nc++ = NPF_OPCODE_RET;
        *nc++ = 0xff;

        npfctl_ncgen_putptr(ctx, nc);

        for (i = 0; i < ctx->nc_jmp_it; i++) {
                ptrdiff_t off = ctx->nc_jmp_list[i] / sizeof(uint32_t);
                uint32_t *jmpop = (uint32_t *)ctx->nc_buf + off;
                uint32_t *jmpval = jmpop + 1;

                *jmpval = foff - off;
        }

        void *buf = ctx->nc_buf;
        *sz = (uintptr_t)ctx->nc_iptr - (uintptr_t)ctx->nc_buf;
        free(ctx->nc_jmp_list);
        free(ctx);
        return buf;
}

void
npfctl_ncgen_group(nc_ctx_t *ctx)
{
        printf("group");
        ctx->nc_saved_it = ctx->nc_jmp_it;
}

void
npfctl_ncgen_endgroup(nc_ctx_t *ctx)
{
        printf("endgroup\n");
        uint32_t *nc;

        /* If there are no fragments or only one - nothing to do. */
        if ((ctx->nc_jmp_it - ctx->nc_saved_it) <= 1) {
                ctx->nc_saved_it = 0;
                return;
        }

        /* Append failure return for OR grouping. */
        nc = npfctl_ncgen_getptr(ctx, 2 /* words */);
        *nc++ = NPF_OPCODE_RET;
        *nc++ = 0xff;
        npfctl_ncgen_putptr(ctx, nc);

        /* Update any group jumps values on success to the current point. */
        size_t i;
        for (i = ctx->nc_saved_it; i < ctx->nc_jmp_it; i++) {
                ptrdiff_t off = ctx->nc_jmp_list[i] / sizeof(uint32_t);
                uint32_t *jmpop = (uint32_t *)ctx->nc_buf + off;
                uint32_t *jmpval = jmpop + 1;


                *jmpop = NPF_OPCODE_BEQ;
                *jmpval = nc - jmpop;
                ctx->nc_jmp_list[i] = 0;
        }

        /* Reset the iterator. */
        ctx->nc_jmp_it = ctx->nc_saved_it;
        ctx->nc_saved_it = 0;
}



void
npfctl_gennc_v4cidr(nc_ctx_t *ctx, int opts, const npf_addr_t *netaddr,
    const npf_netmask_t mask)
{
        uint32_t *nc = npfctl_ncgen_getptr(ctx, 6);
        const uint32_t *addr = (const uint32_t *)netaddr;

        printf("v4cidr\n");

        *nc++ = NPF_OPCODE_IP4MASK;
        *nc++ = (opts & (NC_MATCH_DST | NC_MATCH_SRC)) >> 1;
        *nc++ = addr[0];
        *nc++ = mask;

        npfctl_ncgen_addjmp(ctx, &nc);

        npfctl_ncgen_putptr(ctx, nc);
}
void
npfctl_gennc_ports(nc_ctx_t *ctx, int opts, in_port_t from, in_port_t to)
{
        uint32_t *nc = npfctl_ncgen_getptr(ctx, 5);

        *nc++ = (opts & NC_MATCH_TCP) ?
            NPF_OPCODE_TCP_PORTS : NPF_OPCODE_UDP_PORTS;
        *nc++ = (opts & (NC_MATCH_DST | NC_MATCH_SRC)) >> 1;
        *nc++ = ((uint32_t)from << 16) | to;

        npfctl_ncgen_addjmp(ctx, &nc);

        npfctl_ncgen_putptr(ctx, nc);
}


static void build_ncode(nl_rule_t *rl, unsigned short eport) {
        void *code;
        size_t len;
        int pflag = NC_MATCH_TCP | NC_MATCH_UDP;
        int srcflag = NC_MATCH_SRC;
        int dstflag = NC_MATCH_DST;

        nc_ctx_t *nc = npfctl_ncgen_create();
//      npfctl_ncgen_group(nc);

        npf_addr_t realaddr;
        memset(&realaddr, 0, sizeof(npf_addr_t));
        in_addr_t addr = inet_addr("192.168.0.40");
        memcpy(&realaddr, &addr, sizeof(in_addr_t));
        npfctl_gennc_v4cidr(nc, dstflag, &realaddr, 255);
        npfctl_ncgen_endgroup(nc);

        npfctl_ncgen_group(nc);
        in_port_t port = 0;
        memset(&port, 0, sizeof(in_port_t));
        port = htons(eport);
        npfctl_gennc_ports(nc, (dstflag | pflag) & ~NC_MATCH_UDP, port, port);
        npfctl_gennc_ports(nc, (dstflag | pflag) & ~NC_MATCH_TCP, port, port);
        npfctl_ncgen_endgroup(nc);

        code = npfctl_ncgen_complete(nc, &len);
        printf("len: %d\n", len);
        npf_rule_setcode(rl, NPF_CODE_NCODE, code, len);
        free(code);
}

int init_redirect(void)
{
}

void shutdown_redirect(void)
{
}

int add_redirect_rule2(
        const char * ifname,    /* src interface (external) */
        const char * rhost,     /* remote host (ip) */
        unsigned short eport,   /* src port (external) */
        const char * iaddr,     /* dst address (internal) */
        unsigned short iport,   /* dst port (internal) */
        int proto,
        const char * desc,
        unsigned int timestamp) {
        printf("adding redirect rule, %s %s %u %s %u\n",
    		ifname, rhost, eport, iaddr, iport);

        const int attr_di = (NPF_RULE_IN | NPF_RULE_OUT);

        npf_addr_t realaddr;
        memset(&realaddr, 0, sizeof(npf_addr_t));
        in_addr_t addr = inet_addr(iaddr);
        memcpy(&realaddr, &addr, sizeof(in_addr_t));

        nl_nat_t *nat = npf_nat_create(NPF_NATIN, NPF_NAT_PORTS, 1, &realaddr, AF_INET, htons(iport));
        build_ncode(nat, eport);

        int fd = open("/dev/npf", O_RDONLY);
        npf_add_nat_rule(fd, nat);
        close(fd);

        return 0;

}

int add_filter_rule2(
        const char * ifname,
        const char * rhost,
        const char * iaddr,
        unsigned short eport,
        unsigned short iport,
        int proto,
        const char * desc) {
    	printf("addfilterrule2 %s %s %s %u %u %s\n", ifname, rhost, iaddr, eport, iport, desc);
}

/*
 * get_redirect_rule() gets internal IP and port from
 * interface, external port and protocl
*/
int get_redirect_rule(
        const char * ifname,
        unsigned short eport,
        int proto,
        char * iaddr,
        int iaddrlen,
        unsigned short * iport,
        char * desc,
        int desclen,
        u_int64_t * packets,
        u_int64_t * bytes) {
        printf("getredirect: %s %i %s %u %u %s\n", ifname, eport, iaddr, iport, desc);
}

int get_redirect_rule_by_index(
        int index,
        char * ifname,
        unsigned short * eport,
        char * iaddr,
        int iaddrlen,
        unsigned short * iport,
        int * proto,
        char * desc,
        int desclen,
        u_int64_t * packets,
        u_int64_t * bytes) {
}

/*
 * delete_redirect_rule()
*/
int delete_redirect_rule(const char * ifname, unsigned short eport, int proto) {
	printf("delete redirect rule: %s %u %d\n", ifname, eport, proto);
}

/*
 * delete_filter_rule()
*/
int delete_filter_rule(const char * ifname, unsigned short eport, int proto) {
	printf("delete filter rule: %s %u %d\n", ifname, eport, proto);
}

int clear_redirect_rules(void) {
}

get_portmappings_in_range(unsigned short startport, unsigned short endport,
                          int proto, unsigned int * number) {
	printf("getportmapping %u %u %d\n", startport, endport, proto);
}
