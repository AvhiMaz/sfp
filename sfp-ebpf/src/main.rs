#![no_std]
#![no_main]

#[cfg(not(test))]
use core::panic::PanicInfo;

use aya_ebpf::{
    EbpfContext,
    helpers::generated::bpf_ktime_get_ns,
    macros::{fentry, fexit, map},
    maps::{HashMap, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use sfp_common::LatencyEvent;

#[map]
static START_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 1024, 0);

#[fentry(function = "vfs_read")]
pub fn vf_read_start(ctx: FEntryContext) -> u32 {
    let pid = ctx.pid();
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START_TIME.insert(&pid, &ts, 0);
    0
}

#[fexit(function = "vfs_read")]
pub fn vf_read_exit(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    if let Some(start) = unsafe { START_TIME.get(&pid) } {
        let latency_ns = unsafe { bpf_ktime_get_ns() } - start;
        if let Some(mut entry) = EVENTS.reserve::<LatencyEvent>(0) {
            entry.write(LatencyEvent { pid, latency_ns });
            entry.submit(0);
        }
        let _ = START_TIME.remove(&pid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
pub fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
