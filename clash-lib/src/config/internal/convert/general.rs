use std::net::IpAddr;

use crate::{
    app::net::Interface,
    config::{
        config::{BindAddress, Controller, General},
        def,
    },
};

pub(super) fn convert(c: &def::Config) -> Result<General, crate::Error> {
    let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    };
    Ok(General {
        authentication: c.authentication.clone(),
        controller: Controller {
            external_controller: c.external_controller.clone(),
            external_ui: c.external_ui.clone(),
            secret: c.secret.clone(),
            cors_allow_origins: c.cors_allow_origins.clone(),
            external_controller_ipc: c.external_controller_ipc.clone(),
        },
        mode: c.mode,
        log_level: c.log_level,
        log_timestamp: c.log_timestamp,
        allocator_limit: c.allocator_limit.map(|l| l.0),
        ipv6: c.ipv6,
        interface: c.interface.as_ref().map(|iface| {
            if let Ok(addr) = iface.parse::<IpAddr>() {
                Interface::IpAddr(addr)
            } else {
                Interface::Name(iface.to_string())
            }
        }),
        routing_mask: c.routing_mark,
        mmdb: c.mmdb.to_owned(),
        mmdb_download_url: c.mmdb_download_url.to_owned(),
        asn_mmdb: c.asn_mmdb.to_owned(),
        asn_mmdb_download_url: c.asn_mmdb_download_url.to_owned(),
        geosite: c.geosite.to_owned(),
        geosite_download_url: c.geosite_download_url.to_owned(),
        bind_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::def::Config;

    #[test]
    fn test_convert_log_timestamp() {
        let mut def_config = Config::default();
        def_config.log_timestamp = false;

        let general = convert(&def_config).unwrap();
        assert!(!general.log_timestamp);

        def_config.log_timestamp = true;
        let general = convert(&def_config).unwrap();
        assert!(general.log_timestamp);
    }

    #[test]
    fn test_convert_allocator_limit() {
        use crate::config::def::MemoryLimit;
        
        let mut def_config = Config::default();
        
        // Test None
        let general = convert(&def_config).unwrap();
        assert!(general.allocator_limit.is_none());

        // Test 50MB
        let limit: MemoryLimit = "50MB".to_string().try_into().unwrap();
        def_config.allocator_limit = Some(limit);
        let general = convert(&def_config).unwrap();
        assert_eq!(general.allocator_limit, Some(50 * 1024 * 1024));

        // Test 1GB
        let limit: MemoryLimit = "1GB".to_string().try_into().unwrap();
        def_config.allocator_limit = Some(limit);
        let general = convert(&def_config).unwrap();
        assert_eq!(general.allocator_limit, Some(1 * 1024 * 1024 * 1024));
    }
}
