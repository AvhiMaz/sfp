#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::generated::bpf_ktime_get_ns,
    macros::fentry,
    maps::{HashMap, RingBuf},
    programs::FEntryContext,
};

#[map]
static START_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 1024, 0);

#[fentry(function = "vfs_read")]
pub fn vf_read_start(ctx: FEntryContext) -> u32 {
    let pid = ctx.pid();
    let ts = unsafe { bpf_ktime_get_ns() };
    START_TIME.insert(&pid, &ts, 0);
    0
}
