use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use anyhow::Result;

pub fn get_default_ipv4_gateway() -> Result<String> {
    let cols = get_default_ipv4_route_entry()?;
    // let cols: Vec<&str> = line
    //     .split_whitespace()
    //     .map(str::trim)
    // assert!(cols.len() == 6);
    Ok(cols[5].to_string())
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    let gateway = get_default_ipv4_gateway()?;
    // println!("ipv4 gateway: {:?}", gateway);
    let mut ipv6_gateway = String::default();

    let mut adapters = ipconfig::get_adapters()?;
    adapters.sort_by(|ip1, ip2| ip1.ipv4_metric().cmp(&ip2.ipv4_metric()));
    for adapter in adapters {
        if adapter.gateways().contains(&gateway.parse()?) {
            for ip in adapter.gateways() {
                if ip.is_ipv6() {
                    ipv6_gateway = ip.to_string();
                }
            }
        }
    }
    // println!("ipv6 gateway: {:?}", &ipv6_gateway);
    Ok(ipv6_gateway)
}

pub fn get_default_ipv4_address() -> Result<String> {
    todo!()
}

pub fn get_default_ipv6_address() -> Result<String> {
    todo!()
}

pub fn get_default_interface() -> Result<String> {
    let if_idx = get_default_ipv4_interface_index()?;
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv4")
        .arg("show")
        .arg("interface")
        .output()?;
    // assert!(out.status.success());
    let output = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = output
        .lines()
        .skip(3)
        .map(|line| {
            let a: Vec<&str> = line.split_whitespace().map(str::trim).collect();
            a
        })
        .find(|cols| cols[0] == if_idx.as_str())
        .ok_or(anyhow::anyhow!("cnat get default network iinterface"))?;
    // assert!(cols.len() == 5);
    Ok(cols[4].to_string())
}

use std::io::Write;

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv4")
        .arg("set")
        .arg("address")
        .arg(name)
        .arg("static")
        .arg(addr.to_string())
        .arg(mask.to_string())
        .arg(gw.to_string())
        .arg("store=active")
        .output()?;
    std::io::stdout().write(&out.stdout)?;
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv6")
        .arg("set")
        .arg("address")
        .arg(format!("interface={}", name))
        .arg(format!("address={}", addr.to_string()))
        .arg("store=active")
        .output()?;
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    let mut if_idx = 0;

    let mut adapters = ipconfig::get_adapters()?;
    adapters.sort_by(|ip1, ip2| ip1.ipv4_metric().cmp(&ip2.ipv4_metric()));
    for adapter in adapters {
        if adapter.adapter_name() == interface.as_str() {
            if_idx = adapter.ipv6_if_index();
        }
    }

    let metric = if primary { "metric=1" } else { "" };
    Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv4")
        .arg("add")
        .arg("route")
        .arg("0.0.0.0/0")
        .arg(format!("{}", if_idx).as_str())
        .arg(gateway.to_string())
        .arg(metric)
        .arg("store=active")
        .output()?;
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    let if_idx = get_interface_index(interface.as_str())?;
    Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv6")
        .arg("add")
        .arg("route")
        .arg("::/0")
        .arg(if_idx)
        .arg(gateway.to_string())
        .arg("store=active")
        .output()?;
    Ok(())
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    if let Some(scope) = ifscope {
        let if_idx = get_interface_index(scope.as_str())?;
        let out = Command::new("netsh")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("interface")
            .arg("ipv4")
            .arg("delete")
            .arg("route")
            .arg("::/0")
            .arg("if")
            .arg(if_idx)
            .arg("store=active")
            .output()?;
    } else {
        let out = Command::new("route")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("-6")
            .arg("delete")
            .arg("::/0")
            .output()?;
    }
    Ok(())
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    if let Some(scope) = ifscope {
        let if_idx = get_interface_index(scope.as_str())?;
        let out = Command::new("netsh")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("interface")
            .arg("ipv4")
            .arg("delete")
            .arg("route")
            .arg("0.0.0.0/0")
            .arg("if")
            .arg(if_idx)
            .arg("store=active")
            .output()?;
    } else {
        let out = Command::new("route")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("-4")
            .arg("delete")
            .arg("0.0.0.0/0")
            .output()?;
    }
    Ok(())
}

pub fn add_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Ok(())
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    //  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    todo!()
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    todo!()
}

fn get_default_ipv4_route_entry() -> Result<Vec<String>> {
    let entries = get_ipv4_route_entries()?;
    let e = entries
        .iter()
        .filter(|&e| e[3] == "0.0.0.0/0")
        .last()
        .ok_or(anyhow::anyhow!("cant get default ip route"))?;
    Ok(e.clone())
}

fn get_interface_index(interface: &str) -> Result<String> {
    let col = get_interface_entry(interface)?;
    Ok(col[0].clone())
}

fn get_default_ipv4_interface_index() -> Result<String> {
    let cols = get_default_ipv4_route_entry()?;
    // assert!(cols.len() == 6);
    Ok(cols[4].to_string())
}

fn get_default_ipv6_route_entry() -> Result<String> {
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv6")
        .arg("show")
        .arg("route")
        .output()?;
    // assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let line = out
        .lines()
        .skip(3)
        .next()
        .ok_or(anyhow::anyhow!("cnat get default ipv6 route"))?;
    Ok(line.to_string())
}

fn get_interface_entry(interface: &str) -> Result<Vec<String>> {
    let entries = get_interface_entries()?;
    let entry = entries
        .iter()
        .filter(|&e| e[4].eq(interface))
        .last()
        .ok_or(anyhow::anyhow!("cnat get interface entry"))?
        .clone();
    Ok(entry)
}

fn get_interface_indices() -> Result<Vec<String>> {
    let entires = get_interface_entries()?;
    let indices = entires.iter().map(|e| e[0].to_string()).collect();
    Ok(indices)
}

fn get_interface_entries() -> Result<Vec<Vec<String>>> {
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ip")
        .arg("show")
        .arg("interface")
        .output()?;
    // assert!(out.status.success());
    let output = String::from_utf8_lossy(&out.stdout).to_string();
    let cols = output
        .lines()
        .skip(3)
        .filter(|&line| !line.trim().is_empty())
        .map(|line| {
            let a: Vec<String> = line
                .split_whitespace()
                .map(str::trim)
                .map(str::to_string)
                .collect();
            a
        })
        .collect();
    Ok(cols)
}

fn get_ipv4_route_entries() -> Result<Vec<Vec<String>>> {
    let out = Command::new("netsh")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .arg("interface")
        .arg("ipv4")
        .arg("show")
        .arg("route")
        .output()?;
    // assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let entries = out
        .lines()
        .skip(3)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    Ok(entries)
}
