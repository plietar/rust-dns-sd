extern crate dns_sd;

use dns_sd::DNSService;
use std::time::Duration;

fn main() {
    let svc = DNSService::register(Some("WebServer"),
                                   "_http._tcp",
                                   None,
                                   None,
                                   80,
                                   &["path=/"])
                  .unwrap();

    std::thread::sleep(Duration::from_secs(10));

    drop(svc);
}
