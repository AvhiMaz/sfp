#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LatencyEvent {
    pub pid: u32,
    pub latency_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LatencyEvent {}
