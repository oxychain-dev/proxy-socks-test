use anyhow::{anyhow, Context, Result};
use local_ip_address::list_afinet_netifas;
use reqwest::ClientBuilder;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterfaceTarget {
    pub(super) name: Option<String>,
    pub(super) local_ips: Vec<IpAddr>,
}

impl InterfaceTarget {
    pub(super) fn default_route() -> Self {
        Self { name: None, local_ips: Vec::new() }
    }

    pub(super) fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("default")
    }

    pub(super) fn local_ips_text(&self) -> String {
        self.local_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
    }
}

pub(super) fn select_targets(
    selected: &[String],
    all_interfaces: bool,
) -> Result<Vec<InterfaceTarget>> {
    if !selected.is_empty() && all_interfaces {
        return Err(anyhow!("--interface and --all-interfaces cannot be used together"));
    }
    if selected.is_empty() && !all_interfaces {
        return Ok(vec![InterfaceTarget::default_route()]);
    }

    let entries = list_afinet_netifas().context("failed to enumerate network interfaces")?;
    select_targets_from_entries(entries, selected, all_interfaces)
}

fn select_targets_from_entries(
    entries: Vec<(String, IpAddr)>,
    selected: &[String],
    all_interfaces: bool,
) -> Result<Vec<InterfaceTarget>> {
    let mut by_name: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    for (name, ip) in entries {
        if ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        by_name.entry(name).or_default().insert(ip);
    }

    if all_interfaces {
        let targets = by_name
            .into_iter()
            .filter_map(|(name, ips)| {
                let usable: Vec<_> = ips.into_iter().filter(|ip| !ip.is_loopback()).collect();
                (!usable.is_empty()).then_some(InterfaceTarget {
                    name: Some(name),
                    local_ips: usable,
                })
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err(anyhow!("--all-interfaces found no usable non-loopback interfaces"));
        }
        return Ok(targets);
    }

    let mut unique = BTreeSet::new();
    let mut targets = Vec::new();
    for name in selected {
        if !unique.insert(name.clone()) {
            continue;
        }
        let ips = by_name
            .get(name)
            .ok_or_else(|| anyhow!("network interface not found or has no IP address: {name}"))?
            .iter()
            .copied()
            .collect();
        targets.push(InterfaceTarget { name: Some(name.clone()), local_ips: ips });
    }
    Ok(targets)
}

pub(super) fn bind_client_builder(
    builder: ClientBuilder,
    target: &InterfaceTarget,
) -> Result<ClientBuilder> {
    let Some(name) = target.name.as_deref() else {
        return Ok(builder);
    };

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    {
        Ok(builder.interface(name))
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    )))]
    {
        let ip = target
            .local_ips
            .first()
            .copied()
            .ok_or_else(|| anyhow!("interface {name} has no bindable local address"))?;
        Ok(builder.local_address(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn entries() -> Vec<(String, IpAddr)> {
        vec![
            ("lo".into(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ("eth0".into(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ("eth0".into(), IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ("eth1".into(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        ]
    }

    #[test]
    fn default_route_is_used_without_interface_flags() {
        let targets = select_targets_from_entries(entries(), &[], false).unwrap();
        assert_eq!(targets, vec![InterfaceTarget::default_route()]);
    }

    #[test]
    fn explicit_interface_keeps_all_local_addresses() {
        let targets = select_targets_from_entries(entries(), &["eth0".into()], false).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name.as_deref(), Some("eth0"));
        assert_eq!(targets[0].local_ips.len(), 2);
    }

    #[test]
    fn all_interfaces_excludes_loopback_only_interfaces() {
        let targets = select_targets_from_entries(entries(), &[], true).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets.iter().all(|target| target.name.as_deref() != Some("lo")));
    }

    #[test]
    fn missing_explicit_interface_is_an_error() {
        let err =
            select_targets_from_entries(entries(), &["missing0".into()], false).unwrap_err();
        assert!(err.to_string().contains("missing0"));
    }
}
