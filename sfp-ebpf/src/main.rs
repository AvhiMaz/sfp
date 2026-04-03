#![no_std]
#![no_main]

use aya_ebpf::{macros::fentry, programs::FEntryContext};
use aya_log_ebpf::info;

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

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
