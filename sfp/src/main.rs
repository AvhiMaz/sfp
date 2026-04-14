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

    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sfp"
    )))?;

    Ok(())
}
