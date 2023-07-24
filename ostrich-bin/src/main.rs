use std::process::exit;

use argh::FromArgs;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const COMMIT_HASH: Option<&'static str> = option_env!("CFG_COMMIT_HASH");
const COMMIT_DATE: Option<&'static str> = option_env!("CFG_COMMIT_DATE");

fn get_version_string() -> String {
    match (VERSION, COMMIT_HASH, COMMIT_DATE) {
        (Some(ver), None, None) => ver.to_string(),
        (Some(ver), Some(hash), Some(date)) => {
            format!("{} ({} - {})", ver, hash, date)
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(debug_assertions)]
fn default_thread_stack_size() -> usize {
    2 * 1024 * 1024
}

#[cfg(not(debug_assertions))]
fn default_thread_stack_size() -> usize {
    256 * 1024
}

#[derive(FromArgs)]
/// A lightweight and fast proxy utility
struct Args {
    /// the configuration file
    #[argh(option, short = 'c', default = "String::from(\"config.conf\")")]
    config: String,

    /// enables auto reloading when config file changes
    #[cfg(feature = "auto-reload")]
    #[argh(switch)]
    auto_reload: bool,

    /// runs in a single thread
    #[argh(switch)]
    single_thread: bool,

    /// sets the stack size of runtime worker threads
    #[argh(option, default = "default_thread_stack_size()")]
    thread_stack_size: usize,

    /// tests the configuration and exit
    #[argh(switch, short = 'T')]
    test: bool,

    /// tests the connectivity of the specified outbound
    #[argh(option, short = 't')]
    test_outbound: Option<String>,

    /// timeout for outbound connectivity tests, in seconds
    #[argh(option, short = 'd', default = "4")]
    test_outbound_timeout: u64,

    /// bound interface, explicitly sets the OUTBOUND_INTERFACE environment variable
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[argh(option, short = 'b')]
    boundif: Option<String>,

    /// prints version
    #[argh(switch, short = 'V')]
    version: bool,
}

fn main() {
    let args: Args = argh::from_env();

    if args.version {
        println!("{}", get_version_string());
        exit(0);
    }

    if args.test {
        if let Err(e) = ostrich::test_config(&args.config) {
            println!("{}", e);
            exit(1);
        } else {
            println!("ok");
            exit(0);
        }
    }
    let path = std::env::current_dir().unwrap();
    #[cfg(target_os = "windows")]
    let wintun_path = "C:\\Users\\nancy\\.ostrich\\assets\\wintun.dll";
    #[cfg(target_os = "windows")]
    let tun2socks_path = "C:\\Users\\nancy\\.ostrich\\assets\\tun2socks.exe";
    #[cfg(target_os = "linux")]
    let tun2socks_path = format!(
        "{}/assets/linux/tun2socks",
        path.as_os_str().to_str().unwrap().to_string()
    );
    #[cfg(target_os = "macos")]
    let tun2socks_path = format!(
        "{}/assets/macos/arm/tun2socks",
        path.as_os_str().to_str().unwrap().to_string()
    );
    println!("tun2socks path: {}", tun2socks_path);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(iface) = args.boundif {
        std::env::set_var("OUTBOUND_INTERFACE", &iface);
    }

    if let Some(tag) = args.test_outbound {
        let config = ostrich::config::from_file(&args.config).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match rt.block_on(ostrich::util::test_outbound(
            &tag,
            &config,
            Some(std::time::Duration::from_secs(args.test_outbound_timeout)),
        )) {
            Err(e) => {
                println!("test outbound failed: {}", e);
                exit(1);
            }
            Ok((tcp_res, udp_res)) => {
                match tcp_res {
                    Ok(duration) => println!("TCP ok in {}ms", duration.as_millis()),
                    Err(e) => println!("TCP failed: {}", e),
                }
                match udp_res {
                    Ok(duration) => println!("UDP ok in {}ms", duration.as_millis()),
                    Err(e) => println!("UDP failed: {}", e),
                }
                exit(0);
            }
        }
    }

    if let Err(e) = ostrich::util::run_with_options(
        // 0,
        args.config,
        #[cfg(target_os = "windows")]
        wintun_path.to_string(),
        #[cfg(target_os = "windows")]
        tun2socks_path.to_owned(),
    ) {
        println!("start ostrich failed: {}", e);
        exit(1);
    }
}
