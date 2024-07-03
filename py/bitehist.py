from bcc import BPF
from time import sleep

program = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HISTOGRAM(hist);

int kprobe_blk_accout(struct pt_regs* ctx, struct request *req){
    hist.increment(bpf_log2l(req->__data_len / 1024));
    return 0;
}
"""
# header
print("Tracing... Hit Ctrl-C to end.")
b = BPF(text=program)
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="kprobe_blk_accout")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="kprobe_blk_accout")
# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

b["hist"].print_log2_hist("kbytes")
