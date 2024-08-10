use std::process::Command;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Comittee size
    #[arg(short)]
    n: usize,

    /// Key count
    #[arg(short)]
    k: usize,

    /// Threshold Count
    #[arg(short)]
    t: usize,
}

fn main() {
    let args = Args::parse();

    if args.n != 0 && (args.n & (args.n - 1)) != 0 {
        panic!("n should be a power of two");
    }

    if args.n <= args.k {
        panic!("n can't be equal to or less than k")
    }

    let n = format!("{}", args.n);
    let k = format!("{}", args.k);
    let t = format!("{}", args.t);

    let _  = Command::new("cargo")
        .args(["run", "--release", "--example", "create_keys", "--", "-n", n.as_str(), "-k", k.as_str()])
        .spawn()
        .unwrap()
        .wait();

    let _ = Command::new("cargo")
        .args(["run", "--release", "--example", "encrypt_decrypt", "--", "-n", n.as_str(), "-k", k.as_str(), "-t", t.as_str()])
        .spawn()
        .unwrap()
        .wait();
}