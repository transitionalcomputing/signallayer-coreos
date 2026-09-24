use sl_protocol::{NetworkState, NetworkStatus, PrimaryConnection};
use std::{
    collections::{BTreeSet, HashMap},
    future::pending,
    net::IpAddr,
    time::Duration,
};
use tokio::{sync::Semaphore, time::timeout};
use zbus::proxy::CacheProperties;

const BUS: &str = "org.signallayer.NetworkObserver1";
const PATH: &str = "/org/signallayer/NetworkObserver1";
const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);
const NETWORK_MANAGER_BUS: &str = "org.freedesktop.NetworkManager";
const NETWORK_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const NETWORK_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";
const ACTIVE_CONNECTION_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
const IP4_CONFIG_INTERFACE: &str = "org.freedesktop.NetworkManager.IP4Config";
const IP6_CONFIG_INTERFACE: &str = "org.freedesktop.NetworkManager.IP6Config";

struct Observer {
    connection: zbus::Connection,
    requests: Semaphore,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.signallayer.NetworkObserver1.Error")]
enum ObserverError {
    Busy(String),
    Unavailable(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

#[zbus::interface(name = "org.signallayer.NetworkObserver1")]
impl Observer {
    async fn get_network_status(&self) -> Result<String, ObserverError> {
        let _permit = self.requests.try_acquire().map_err(|_| {
            ObserverError::Busy("A network observation is already in progress".into())
        })?;
        let status = observe_network(&self.connection)
            .await
            .map_err(|_| unavailable())?;
        serde_json::to_string(&status).map_err(|_| unavailable())
    }
}

fn unavailable() -> ObserverError {
    ObserverError::Unavailable("NetworkManager status could not be observed or was invalid".into())
}

fn network_state(value: u32) -> NetworkState {
    match value {
        10 | 20 | 30 => NetworkState::Disconnected,
        40 => NetworkState::Connecting,
        50 => NetworkState::ConnectedLocal,
        60 => NetworkState::ConnectedSite,
        70 => NetworkState::ConnectedGlobal,
        _ => NetworkState::Unknown,
    }
}

fn parse_address_data(
    entries: Vec<HashMap<String, zbus::zvariant::OwnedValue>>,
    family: u8,
) -> Result<BTreeSet<String>, ()> {
    entries
        .into_iter()
        .map(|mut entry| {
            let address: String = entry
                .remove("address")
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?;
            let prefix: u32 = entry
                .remove("prefix")
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?;
            let parsed: IpAddr = address.parse().map_err(|_| ())?;
            if (family == 4 && (!parsed.is_ipv4() || prefix > 32))
                || (family == 6 && (!parsed.is_ipv6() || prefix > 128))
            {
                return Err(());
            }
            Ok(format!("{parsed}/{prefix}"))
        })
        .collect()
}

fn parse_gateway(value: String, family: u8) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    let parsed: IpAddr = value.parse().map_err(|_| ())?;
    if (family == 4 && !parsed.is_ipv4()) || (family == 6 && !parsed.is_ipv6()) {
        return Err(());
    }
    Ok(Some(parsed.to_string()))
}

async fn proxy<'a>(
    connection: &'a zbus::Connection,
    path: &'a str,
    interface: &'a str,
) -> zbus::Result<zbus::Proxy<'a>> {
    zbus::proxy::Builder::<zbus::Proxy<'_>>::new(connection)
        .destination(NETWORK_MANAGER_BUS)?
        .path(path)?
        .interface(interface)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

async fn observe_network(connection: &zbus::Connection) -> Result<NetworkStatus, ()> {
    timeout(NETWORK_TIMEOUT, async {
        let manager = proxy(connection, NETWORK_MANAGER_PATH, NETWORK_MANAGER_INTERFACE).await?;
        let state: u32 = manager.get_property("State").await?;
        let primary_path: zbus::zvariant::OwnedObjectPath =
            manager.get_property("PrimaryConnection").await?;
        if primary_path.as_str() == "/" {
            return Ok(NetworkStatus {
                state: network_state(state),
                primary_connection: None,
            });
        }
        let active = proxy(
            connection,
            primary_path.as_str(),
            ACTIVE_CONNECTION_INTERFACE,
        )
        .await?;
        let devices: Vec<zbus::zvariant::OwnedObjectPath> = active.get_property("Devices").await?;
        if devices.len() != 1 {
            return Err(zbus::Error::Failure(
                "The primary connection does not identify exactly one device".into(),
            ));
        }
        let device = proxy(connection, devices[0].as_str(), DEVICE_INTERFACE).await?;
        let interface: String = device.get_property("Interface").await?;
        if interface.is_empty()
            || interface.len() > 64
            || interface
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(zbus::Error::Failure("Invalid primary interface".into()));
        }

        let mut addresses = BTreeSet::new();
        let mut gateways = BTreeSet::new();
        for (path_property, default_property, config_interface, family) in [
            ("Ip4Config", "Default", IP4_CONFIG_INTERFACE, 4),
            ("Ip6Config", "Default6", IP6_CONFIG_INTERFACE, 6),
        ] {
            let path: zbus::zvariant::OwnedObjectPath = active.get_property(path_property).await?;
            if path.as_str() == "/" {
                continue;
            }
            let config = proxy(connection, path.as_str(), config_interface).await?;
            let data: Vec<HashMap<String, zbus::zvariant::OwnedValue>> =
                config.get_property("AddressData").await?;
            addresses.extend(
                parse_address_data(data, family).map_err(|_| {
                    zbus::Error::Failure("Invalid NetworkManager address data".into())
                })?,
            );
            let is_default: bool = active.get_property(default_property).await?;
            if is_default {
                let gateway: String = config.get_property("Gateway").await?;
                if let Some(gateway) = parse_gateway(gateway, family)
                    .map_err(|_| zbus::Error::Failure("Invalid NetworkManager gateway".into()))?
                {
                    gateways.insert(gateway);
                }
            }
        }
        Ok::<_, zbus::Error>(NetworkStatus {
            state: network_state(state),
            primary_connection: Some(PrimaryConnection {
                interface,
                addresses: addresses.into_iter().collect(),
                default_gateways: gateways.into_iter().collect(),
            }),
        })
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = zbus::connection::Builder::system()?.build().await?;
    connection
        .object_server()
        .at(
            PATH,
            Observer {
                connection: connection.clone(),
                requests: Semaphore::new(1),
            },
        )
        .await?;
    connection.request_name(BUS).await?;
    pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_state_mapping_is_documented_and_complete() {
        assert_eq!(network_state(0), NetworkState::Unknown);
        assert_eq!(network_state(10), NetworkState::Disconnected);
        assert_eq!(network_state(20), NetworkState::Disconnected);
        assert_eq!(network_state(30), NetworkState::Disconnected);
        assert_eq!(network_state(40), NetworkState::Connecting);
        assert_eq!(network_state(50), NetworkState::ConnectedLocal);
        assert_eq!(network_state(60), NetworkState::ConnectedSite);
        assert_eq!(network_state(70), NetworkState::ConnectedGlobal);
        assert_eq!(network_state(999), NetworkState::Unknown);
    }

    #[test]
    fn network_addresses_are_validated_sorted_and_deduplicated() {
        let entry = |address: &str, prefix: u32| {
            HashMap::from([
                (
                    "address".into(),
                    zbus::zvariant::OwnedValue::from(zbus::zvariant::Str::from(address)),
                ),
                ("prefix".into(), zbus::zvariant::OwnedValue::from(prefix)),
            ])
        };
        let addresses = parse_address_data(
            vec![
                entry("10.0.2.15", 24),
                entry("192.0.2.2", 24),
                entry("10.0.2.15", 24),
            ],
            4,
        )
        .unwrap();
        assert_eq!(
            addresses.into_iter().collect::<Vec<_>>(),
            vec!["10.0.2.15/24", "192.0.2.2/24"]
        );
        assert!(parse_address_data(vec![entry("10.0.2.15", 33)], 4).is_err());
        assert!(parse_address_data(vec![entry("2001:db8::1", 64)], 4).is_err());
        assert_eq!(
            parse_gateway("2001:0db8::1".into(), 6).unwrap(),
            Some("2001:db8::1".into())
        );
        assert!(parse_gateway("2001:db8::1".into(), 4).is_err());
    }
}
