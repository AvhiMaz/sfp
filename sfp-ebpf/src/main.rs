#![no_std]
#![no_main]

use aya_ebpf::{
    macros::fentry,
    maps::{HashMap, RingBuf},
    programs::FEntryContext,
};
use aya_log_ebpf::info;

static START_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 1024, 0);

#[fentry(function = "vfs_read")]
pub fn sfp(ctx: FEntryContext) -> u32 {
    match try_sfp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sfp(ctx: FEntryContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_read called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
