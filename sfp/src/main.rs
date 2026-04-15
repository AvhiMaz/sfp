use clap::Parser;
use libc::{RLIM_INFINITY, RLIMIT_MEMLOCK, rlimit, setrlimit};
use log::debug;

#[derive(Parser, Debug)]
struct Opt {
    #[arg(short, long)]
    pid: Vec<u32>,
    #[arg(long)]
    histogram: bool,
    #[arg(long)]
    files: bool,
}

struct Histogram {
    buckets: [u64; 5],
}

impl Histogram {
    fn new() -> Self {
        Self { buckets: [0; 5] }
    }

    fn record(&mut self, latency_ns: u64) {
        let idx = if latency_ns < 1_000 {
            0
        } else if latency_ns < 10_000 {
            1
        } else if latency_ns < 100_000 {
            2
        } else if latency_ns < 1_000_000 {
            3
        } else {
            4
        };
        self.buckets[idx] += 1;
    }

    fn print(&self) {
        let labels = ["    <1µs", "  1-10µs", "10-100µs", "100µs-1ms", "    >1ms"];
        let total: u64 = self.buckets.iter().sum();
        println!("vfs_read latency histogram (total: {})", total);
        if total == 0 {
            println!("  (no events yet)");
            return;
        }
        let max = *self.buckets.iter().max().unwrap();
        for (i, &count) in self.buckets.iter().enumerate() {
            let bar_len = (count * 40 / max.max(1)) as usize;
            let bar = "█".repeat(bar_len);
            println!("  {}  {:40}  {}", labels[i], bar, count);
        }
    }
}

fn parse_filename(filename: &[u8; 256]) -> &str {
    let end = filename.iter().position(|&b| b == 0).unwrap_or(256);
    std::str::from_utf8(&filename[..end]).unwrap_or("<invalid>")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();
    let mut histogram = Histogram::new();
    let mut total_events: u64 = 0;

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

                        total_events += 1;
                        if opt.pid.is_empty() || opt.pid.contains(&event.pid) {
                            if opt.files {
                                let fname = parse_filename(&event.filename);
                                let skip = matches!(fname, "ptmx" | "tty" | "TCP" | "UDP" | "UNIX-STREAM" | "<empty>");
                                if !skip {
                                    println!("pid: {:6}  file: {:<30}  latency: {:>10}ns", event.pid, fname, event.latency_ns);
                                }
                            } else {
                                histogram.record(event.latency_ns);
                            }
                        }
                    }
                }
                g.clear_ready();
            }
        }
    }

    println!("total events captured: {}", total_events);

    if opt.histogram {
        histogram.print();
    }

    Ok(())
}
