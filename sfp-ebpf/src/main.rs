#![no_std]
#![no_main]

#[cfg(not(test))]
use core::panic::PanicInfo;

mod vmlinux;
use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_buf, generated::bpf_ktime_get_ns},
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
    let _ = START_TIME.insert(pid, ts, 0);
    0
}

#[fexit(function = "vfs_read")]
pub fn vf_read_exit(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    if let Some(start) = unsafe { START_TIME.get(&pid) } {
        let latency_ns = unsafe { bpf_ktime_get_ns() } - start;
        if let Some(mut entry) = EVENTS.reserve::<LatencyEvent>(0) {
            let file_ptr: *const vmlinux::file = unsafe { ctx.arg(0) };
            let mut filename = [0u8; 256];
            unsafe {
                if let Ok(dentry_ptr) =
                    bpf_probe_read_kernel(core::ptr::addr_of!((*file_ptr).f_path.dentry)
                        as *const *mut vmlinux::dentry)
                {
                    if let Ok(name_ptr) = bpf_probe_read_kernel(core::ptr::addr_of!(
                        (*dentry_ptr).d_name.name
                    )
                        as *const *const u8)
                    {
                        let _ = bpf_probe_read_kernel_buf(name_ptr, &mut filename);
                    }
                }
            }
            entry.write(LatencyEvent {
                pid,
                latency_ns,
                filename,
            });
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
