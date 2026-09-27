//! On-link eligibility from Session1's status (schema 0.4), the only source of
//! network truth. Everything that is missing or ambiguous fails closed.
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

pub const PORT: u16 = 8443;
const SESSION_SCHEMA: &str = "0.4";

// Only the fields sl-remoted needs; everything else in the status is ignored.
#[derive(Deserialize)]
struct Status {
    schema_version: String,
    network: Network,
}

#[derive(Deserialize)]
struct Network {
    primary_connection: Option<Primary>,
}

#[derive(Deserialize)]
struct Primary {
    addresses: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    network: IpAddr,
    length: u8,
}

impl Prefix {
    fn new(address: IpAddr, length: u8) -> Self {
        Self {
            network: mask(address, length),
            length,
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        address.is_ipv4() == self.network.is_ipv4() && mask(address, self.length) == self.network
    }
}

fn mask(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            IpAddr::V6((bits & mask).into())
        }
    }
}

/// The published network view: where to listen, and which sources are on-link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    pub listen: Vec<IpAddr>,
    pub prefixes: Vec<Prefix>,
}

fn listenable(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && address.segments()[0] & 0xffc0 != 0xfe80
        }
    }
}

/// No primary connection is an empty view (nothing listens). A wrong schema,
/// an unparsable address or a `/0` prefix is ambiguous and is an error.
pub fn view_from_status(json: &str) -> Result<View, ()> {
    let status: Status = serde_json::from_str(json).map_err(|_| ())?;
    if status.schema_version != SESSION_SCHEMA {
        return Err(());
    }
    let Some(primary) = status.network.primary_connection else {
        return Ok(View::default());
    };
    let mut view = View::default();
    for entry in &primary.addresses {
        let (address, length) = entry.split_once('/').ok_or(())?;
        let address: IpAddr = address.parse().map_err(|_| ())?;
        let length: u8 = length.parse().map_err(|_| ())?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if length == 0 || length > maximum {
            return Err(());
        }
        view.prefixes.push(Prefix::new(address, length));
        if listenable(&address) && !view.listen.contains(&address) {
            view.listen.push(address);
        }
    }
    Ok(view)
}

/// IPv4-mapped IPv6 sources are compared as IPv4.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        IpAddr::V4(_) => address,
    }
}

pub fn on_link(view: &View, source: IpAddr) -> bool {
    let source = canonical(source);
    view.prefixes.iter().any(|prefix| prefix.contains(source))
}

/// The exact Host value (and Origin authority) for a listener endpoint.
pub fn endpoint(local: SocketAddr) -> String {
    match local.ip() {
        IpAddr::V4(address) => format!("{address}:{}", local.port()),
        IpAddr::V6(address) => format!("[{address}]:{}", local.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(addresses: &[&str]) -> String {
        serde_json::json!({
            "schema_version": "0.4",
            "product": "ignored",
            "network": {"state": "connected_global", "primary_connection": {
                "interface": "enp0s2", "addresses": addresses, "default_gateways": []}},
            "remote_management": {"enabled": true, "listening": false, "enrolled": true}
        })
        .to_string()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ipv4_on_link_boundaries() {
        let view = view_from_status(&status(&["192.0.2.10/24"])).unwrap();
        assert_eq!(view.listen, [ip("192.0.2.10")]);
        for inside in ["192.0.2.0", "192.0.2.1", "192.0.2.10", "192.0.2.255"] {
            assert!(on_link(&view, ip(inside)), "{inside}");
        }
        for outside in [
            "192.0.1.255",
            "192.0.3.0",
            "10.0.0.1",
            "0.0.0.0",
            "2001:db8::1",
        ] {
            assert!(!on_link(&view, ip(outside)), "{outside}");
        }
        // IPv4-mapped IPv6 sources are treated as IPv4.
        assert!(on_link(&view, ip("::ffff:192.0.2.77")));
        assert!(!on_link(&view, ip("::ffff:192.0.3.77")));
    }

    #[test]
    fn ipv6_on_link_boundaries() {
        let view = view_from_status(&status(&["2001:db8:1:2::10/64", "fe80::1/64"])).unwrap();
        assert_eq!(
            view.listen,
            [ip("2001:db8:1:2::10")],
            "link-local is never bound"
        );
        for inside in [
            "2001:db8:1:2::",
            "2001:db8:1:2:ffff:ffff:ffff:ffff",
            "fe80::abcd",
        ] {
            assert!(on_link(&view, ip(inside)), "{inside}");
        }
        for outside in [
            "2001:db8:1:3::1",
            "2001:db8:1:1:ffff:ffff:ffff:ffff",
            "fe81::1",
            "192.0.2.1",
        ] {
            assert!(!on_link(&view, ip(outside)), "{outside}");
        }
    }

    #[test]
    fn odd_prefix_lengths_mask_exactly() {
        let view = view_from_status(&status(&["10.1.2.3/31", "2001:db8::5/127"])).unwrap();
        assert!(on_link(&view, ip("10.1.2.2")));
        assert!(!on_link(&view, ip("10.1.2.4")));
        assert!(on_link(&view, ip("2001:db8::4")));
        assert!(!on_link(&view, ip("2001:db8::6")));
        let host = view_from_status(&status(&["10.9.9.9/32", "2001:db8::9/128"])).unwrap();
        assert!(on_link(&host, ip("10.9.9.9")));
        assert!(!on_link(&host, ip("10.9.9.8")));
        assert!(!on_link(&host, ip("2001:db8::8")));
    }

    #[test]
    fn non_listenable_addresses_are_never_bound() {
        let view = view_from_status(&status(&[
            "127.0.0.1/8",
            "169.254.1.1/16",
            "fe80::1/64",
            "::1/128",
            "192.0.2.10/24",
            "192.0.2.10/24",
        ]))
        .unwrap();
        assert_eq!(view.listen, [ip("192.0.2.10")]);
    }

    #[test]
    fn missing_or_ambiguous_state_fails_closed() {
        let no_primary = serde_json::json!({"schema_version": "0.4",
            "network": {"state": "disconnected", "primary_connection": null}})
        .to_string();
        assert_eq!(view_from_status(&no_primary), Ok(View::default()));
        let wrong_schema = status(&["192.0.2.10/24"]).replace("\"0.4\"", "\"0.3\"");
        for invalid in [
            wrong_schema,
            status(&["192.0.2.10/0"]),
            status(&["::/0"]),
            status(&["192.0.2.10/33"]),
            status(&["2001:db8::1/129"]),
            status(&["192.0.2.10"]),
            status(&["not-an-address/24"]),
            status(&["192.0.2.10/x"]),
            "{}".into(),
            "not json".into(),
            serde_json::json!({"schema_version": "0.4"}).to_string(),
        ] {
            assert_eq!(view_from_status(&invalid), Err(()), "{invalid}");
        }
    }

    #[test]
    fn endpoints_are_exact_and_bracketed() {
        assert_eq!(
            endpoint("192.0.2.10:8443".parse().unwrap()),
            "192.0.2.10:8443"
        );
        assert_eq!(
            endpoint("[2001:db8:0:0::10]:8443".parse().unwrap()),
            "[2001:db8::10]:8443"
        );
    }
}
