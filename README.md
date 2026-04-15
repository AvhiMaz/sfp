# sfp

an ebpf tool written in rust using [aya](https://github.com/aya-rs/aya) that hooks into `vfs_read` via `fentry`/`fexit` to measure file read latency in nanoseconds.

> i’ve done everything on macos, but we can’t run it directly because ebpf requires a linux kernel. we’ll need a linux vm to run this. this project uses [lima](https://github.com/lima-vm/lima) for development on macos.

---

### cli flags

| flag          | description                                                |
| ------------- | ---------------------------------------------------------- |
| `--files`     | print live per-file latency: `pid / filename / latency_ns` |
| `--histogram` | accumulate into latency buckets, print histogram on exit   |
