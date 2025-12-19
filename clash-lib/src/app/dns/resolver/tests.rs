use super::EnhancedResolver;
use std::sync::Arc;

#[tokio::test]
async fn test_geoip_cache_update_and_hit() {
    use crate::app::profile::{GeoIPCacheEntry, ThreadSafeCacheFile};
    use tempfile::NamedTempFile;

    // Mock config
    let file = NamedTempFile::new().unwrap();
    let store = ThreadSafeCacheFile::new(file.path().to_str().unwrap(), true);
    
    // Mock Mmdb
    // Since we can't easily mock MmdbLookupTrait due to its internal structure in this context,
    // we will test the logic flow by manually manipulating the cache store.
    
    let domain = "example.com";
    let code = "CN";
    let entry = GeoIPCacheEntry {
        code: code.to_string(),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600,
    };

    // 1. Manually set cache
    store.set_domain_geoip(domain, entry.clone()).await;

    // 2. Verify cache retrieval
    let cached = store.get_domain_geoip(domain).await;
    assert!(cached.is_some());
    let cached = cached.unwrap();
    assert_eq!(cached.code, code);
    assert!(cached.expires_at > 0);

    // 3. Create a resolver with mocked components (conceptually)
    // Here we verify that the resolver logic would use this cache.
    // Since `ip_exchange` is complex to unit test in isolation without full network mocks,
    // we focus on verifying the `store` integration which we modified.
    
    // 4. Test expiration logic
    let expired_entry = GeoIPCacheEntry {
        code: "US".to_string(),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 10, // Expired
    };
    store.set_domain_geoip("expired.com", expired_entry).await;
    
    let expired = store.get_domain_geoip("expired.com").await;
    assert!(expired.is_some());
    // In the real resolver logic, we check `expires_at > now`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expired.unwrap().expires_at < now);
}

// Mock DNS Server
struct MockDnsServer {
    socket: tokio::net::UdpSocket,
    ip: std::net::Ipv4Addr,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

impl MockDnsServer {
    async fn new(ip: std::net::Ipv4Addr, requests: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self { socket, ip, requests }
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.socket.local_addr().unwrap()
    }

    async fn run(self) {
        let mut buf = [0u8; 512];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await.unwrap();
            self.requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let request = hickory_proto::op::Message::from_vec(&buf[..len]).unwrap();
            
            let mut response = hickory_proto::op::Message::new();
            response.set_id(request.id());
            response.set_message_type(hickory_proto::op::MessageType::Response);
            response.set_op_code(hickory_proto::op::OpCode::Query);
            response.set_recursion_desired(true);
            response.set_recursion_available(true);
            response.add_query(request.query().unwrap().clone());

            let record = hickory_proto::rr::Record::from_rdata(
                request.query().unwrap().name().clone(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(self.ip)),
            );
            response.add_answer(record);

            let response_bytes = response.to_vec().unwrap();
            self.socket.send_to(&response_bytes, src).await.unwrap();
        }
    }
}

struct MockMmdb {
    data: std::collections::HashMap<std::net::IpAddr, String>,
}

impl crate::common::mmdb::MmdbLookupTrait for MockMmdb {
    fn lookup_country(&self, ip: std::net::IpAddr) -> std::io::Result<crate::common::mmdb::MmdbLookupCountry> {
        if let Some(code) = self.data.get(&ip) {
            Ok(crate::common::mmdb::MmdbLookupCountry {
                country_code: code.clone(),
            })
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
        }
    }
    
    fn lookup_asn(&self, _ip: std::net::IpAddr) -> std::io::Result<crate::common::mmdb::MmdbLookupAsn> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
    }
}

#[tokio::test]
async fn test_geoip_integration_flow() {
    use crate::app::profile::ThreadSafeCacheFile;
    use crate::app::dns::Config;
    use crate::app::dns::config::{NameServer, FallbackFilter};
    use crate::app::dns::ClashResolver;
    use tempfile::NamedTempFile;
    use std::collections::HashMap;
    use std::sync::Arc;

    use std::sync::atomic::AtomicUsize;

    // 1. Setup Mock DNS Servers
    let main_requests = Arc::new(AtomicUsize::new(0));
    let main_server = MockDnsServer::new(std::net::Ipv4Addr::new(1, 1, 1, 1), main_requests.clone()).await;
    let main_addr = main_server.addr();
    tokio::spawn(main_server.run());

    let fallback_requests = Arc::new(AtomicUsize::new(0));
    let fallback_server = MockDnsServer::new(std::net::Ipv4Addr::new(2, 2, 2, 2), fallback_requests.clone()).await;
    let fallback_addr = fallback_server.addr();
    tokio::spawn(fallback_server.run());

    // 2. Setup Mock Mmdb
    let mut mmdb_data = HashMap::new();
    mmdb_data.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), "CN".to_string());
    mmdb_data.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(2, 2, 2, 2)), "US".to_string());
    let mmdb = Arc::new(MockMmdb { data: mmdb_data });

    // 3. Setup Cache Store
    let file = NamedTempFile::new().unwrap();
    let store = ThreadSafeCacheFile::new(file.path().to_str().unwrap(), true);

    // 4. Setup Config
    let mut config = Config::default();
    config.enable = true;
    config.nameserver = vec![NameServer {
        net: crate::app::dns::dns_client::DNSNetMode::Udp,
        address: main_addr.to_string(),
        interface: None,
        proxy: None,
    }];
    config.fallback = vec![NameServer {
        net: crate::app::dns::dns_client::DNSNetMode::Udp,
        address: fallback_addr.to_string(),
        interface: None,
        proxy: None,
    }];
    config.fallback_filter = FallbackFilter {
        geo_ip: true,
        geo_ip_code: "CN".to_string(),
        geo_ip_cache_expiration: Some(60),
        match_noproxy: false,
        ip_cidr: None,
        domain: vec![],
    };

    // 5. Create EnhancedResolver
    let resolver = EnhancedResolver::new(
        config,
        store.clone(),
        Some(mmdb),
        HashMap::new(),
    ).await;

    // Test 1: Cache Miss -> Match -> Main
    let res = resolver.resolve("test1.com", true).await.unwrap();
    assert_eq!(res, Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))));

    // Check Cache
    tokio::time::sleep(std::time::Duration::from_millis(100)).await; // Wait for async update
    let cached = store.get_domain_geoip("test1.com").await;
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().code, "CN");

    // Test 2: Cache Hit (CN) -> Trust Main (even if we force Main to return something else, but here Main is static)
    // Logic: Skip fallback check, use Main result.
    let res = resolver.resolve("test1.com", true).await.unwrap();
    assert_eq!(res, Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))));

    // Test 3: Cache Mismatch -> Force Fallback
    // Manually inject a US cache entry
    let us_entry = crate::app::profile::GeoIPCacheEntry {
        code: "US".to_string(),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600,
    };
    store.set_domain_geoip("test2.com", us_entry).await;

    // Record requests before query
    let main_count_before = main_requests.load(std::sync::atomic::Ordering::SeqCst);

    let res = resolver.resolve("test2.com", true).await.unwrap();
    // Should use Fallback (2.2.2.2) because Cache says US (mismatch CN), so we force fallback.
    // Fallback server returns 2.2.2.2.
    assert_eq!(res, Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(2, 2, 2, 2))));

    // Verify Main server was NOT queried
    let main_count_after = main_requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(main_count_before, main_count_after, "Main server should not be queried when cache mismatch triggers fallback");
}

#[tokio::test]
async fn test_geoip_fallback_fake_ip() {
    use crate::app::profile::ThreadSafeCacheFile;
    use crate::app::dns::Config;
    use crate::app::dns::config::{NameServer, FallbackFilter};
    use crate::app::dns::ClashResolver;
    use crate::config::def::DNSMode;
    use tempfile::NamedTempFile;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    // 1. Setup Mock DNS Servers
    let main_requests = Arc::new(AtomicUsize::new(0));
    let main_server = MockDnsServer::new(std::net::Ipv4Addr::new(1, 1, 1, 1), main_requests.clone()).await;
    let main_addr = main_server.addr();
    tokio::spawn(main_server.run());

    let fallback_requests = Arc::new(AtomicUsize::new(0));
    let fallback_server = MockDnsServer::new(std::net::Ipv4Addr::new(2, 2, 2, 2), fallback_requests.clone()).await;
    let fallback_addr = fallback_server.addr();
    tokio::spawn(fallback_server.run());

    // 2. Setup Mock Mmdb
    let mut mmdb_data = HashMap::new();
    mmdb_data.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), "US".to_string());
    let mmdb = Arc::new(MockMmdb { data: mmdb_data });

    // 3. Setup Cache Store
    let file = NamedTempFile::new().unwrap();
    let store = ThreadSafeCacheFile::new(file.path().to_str().unwrap(), true);

    // 4. Setup Config
    let mut config = Config::default();
    config.enable = true;
    config.enhance_mode = DNSMode::FakeIp;
    config.fake_ip_range = "198.18.0.1/16".parse().unwrap();
    config.nameserver = vec![NameServer {
        net: crate::app::dns::dns_client::DNSNetMode::Udp,
        address: main_addr.to_string(),
        interface: None,
        proxy: None,
    }];
    config.fallback = vec![NameServer {
        net: crate::app::dns::dns_client::DNSNetMode::Udp,
        address: fallback_addr.to_string(),
        interface: None,
        proxy: None,
    }];
    config.fallback_filter = FallbackFilter {
        geo_ip: true,
        geo_ip_code: "CN".to_string(),
        match_noproxy: true,
        geo_ip_cache_expiration: None,
        ip_cidr: None,
        domain: vec![],
    };

    // 5. Create EnhancedResolver
    let resolver = EnhancedResolver::new(
        config,
        store.clone(),
        Some(mmdb),
        HashMap::new(),
    ).await;

    // Test: Main returns 1.1.1.1 (US), mismatch CN.
    // match_noproxy is true, and FakeIP is enabled.
    // Should return a FakeIP.
    let res = resolver.resolve("test_fake.com", true).await.unwrap();
    
    assert!(res.is_some());
    let ip = res.unwrap();
    // Verify it is a FakeIP (198.18.x.x)
    match ip {
        std::net::IpAddr::V4(v4) => {
            assert!(v4.octets()[0] == 198 && v4.octets()[1] == 18);
        },
        _ => panic!("Expected IPv4 FakeIP"),
    }
}
