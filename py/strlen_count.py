from bcc import BPF
from time import sleep
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/string.h> 
struct key_t {
    char c[80];
};
BPF_HASH(counts,struct key_t);

int count(struct pt_regs* ctx){
    if(!PT_REGS_PARM1(ctx)){
        return 0;
    }
    struct key_t key = {};
    u64 zero = 0, *val;
    bpf_probe_read_user(&key.c, sizeof(key.c), (void*)PT_REGS_PARM1(ctx));
    val = counts.lookup_or_try_init(&key, &zero);
    if(val){
        (*val)++;
    }
    return 0;
}

"""

b = BPF(text=program)
b.attach_uprobe(name="c", sym="strlen", fn_name="count")
# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

counts = b.get_table("counts")
for k,v in sorted(counts.items(), key = lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
    