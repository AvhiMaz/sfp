use clap::Parser;
use libc::{RLIM_INFINITY, RLIMIT_MEMLOCK, rlimit, setrlimit};
use log::debug;

#[derive(Parser, Debug)]
struct Opt {
    #[arg(short, long)]
    pid: Vec<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let rlimit = rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    let ret = unsafe { setrlimit(RLIMIT_MEMLOCK, &rlimit) };

    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sfp"
    )))?;

    let btf = aya::Btf::from_sys_fs()?;

    let fentry: &mut aya::programs::FEntry =
        ebpf.program_mut("vf_read_start").unwrap().try_into()?;
    fentry.load("vfs_read", &btf)?;
    fentry.attach()?;

    let fexit: &mut aya::programs::FExit = ebpf.program_mut("vf_read_exit").unwrap().try_into()?;
    fexit.load("vfs_read", &btf)?;
    fexit.attach()?;

    let ring_buffer = aya::maps::RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;

    let mut fd = tokio::io::unix::AsyncFd::new(ring_buffer)?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            result = fd.readable_mut() => {
                let mut g = result?;
                let rb = g.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= std::mem::size_of::<sfp_common::LatencyEvent>() {
                        let event = unsafe {
                            (item.as_ptr() as *const sfp_common::LatencyEvent).read_unaligned()
                        };

                        if opt.pid.is_empty() || opt.pid.contains(&event.pid) {
                            println!("pid: {}, latency_ns: {}", event.pid, event.latency_ns);
                        }
                    }
                }
                g.clear_ready();
            }
        }
    }

    Ok(())
}
