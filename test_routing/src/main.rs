use reqwest::Client;
use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Building clash-rs...");
    let build_status = Command::new("cargo")
        .args(&["build"])
        .current_dir("..")
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }

    println!("Starting clash-rs...");
    // Kill any existing clash-rs instance
    let _ = Command::new("pkill").arg("clash-rs").status();

    let mut clash_process = Command::new("./target/debug/clash-rs")
        .args(&["-c", "clash-bin/tests/data/config/geoip-fallback-test.yaml"])
        .current_dir("..")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Wait for clash to start
    println!("Waiting for clash-rs to initialize...");
    thread::sleep(Duration::from_secs(10));

    let proxy_url = "http://127.0.0.1:7890";
    println!("Using proxy: {}", proxy_url);

    let client = Client::builder()
        .proxy(reqwest::Proxy::all(proxy_url)?)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("\n---------------------------------------------------");
    println!("Testing baidu.com (should be DIRECT)...");
    println!("---------------------------------------------------");
    // Since we are in China (likely, given the tests), baidu should work via DIRECT
    match client.get("http://www.baidu.com").send().await {
        Ok(resp) => println!(">>> baidu.com check: OK (Status: {})", resp.status()),
        Err(e) => println!(">>> baidu.com check: FAILED ({})", e),
    }

    println!("\n---------------------------------------------------");
    println!("Testing google.com (should be PROXY)...");
    println!("---------------------------------------------------");
    // This will likely fail connection-wise because the upstream proxy in config is
    // dummy, BUT we want to see the clash-rs logs showing the routing decision.
    match client.get("http://www.google.com").send().await {
        Ok(resp) => println!(">>> google.com check: OK (Status: {})", resp.status()),
        Err(e) => println!(
            ">>> google.com check: FAILED ({}) \n(This is expected if upstream \
             proxy is invalid, check clash logs for routing decision)",
            e
        ),
    }

    println!("\n---------------------------------------------------");
    println!("Testing 1.1.1.1 (Pure IP)...");
    println!("---------------------------------------------------");
    match client.get("http://1.1.1.1:9413").send().await {
        Ok(resp) => println!(">>> 1.1.1.1 check: OK (Status: {})", resp.status()),
        Err(e) => println!(">>> 1.1.1.1 check: FAILED ({})", e),
    }

    println!("\nStopping clash-rs...");
    clash_process.kill()?;
    clash_process.wait()?;

    Ok(())
}
