pub(super) const PERMIT_WEIGHT: u8 = 15;
pub(super) const BLOCK_WEIGHT: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layer {
    AuthConnectV4,
    AuthConnectV6,
    FlowEstablishedV4,
    FlowEstablishedV6,
}

impl Layer {
    pub(super) fn is_ipv4(self) -> bool {
        matches!(self, Self::AuthConnectV4 | Self::FlowEstablishedV4)
    }
}

pub(super) const LAYERS: [Layer; 4] = [
    Layer::AuthConnectV4,
    Layer::AuthConnectV6,
    Layer::FlowEstablishedV4,
    Layer::FlowEstablishedV6,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PermitV4 {
    pub(super) label: &'static str,
    pub(super) addr: u32,
    pub(super) mask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PermitV6 {
    pub(super) label: &'static str,
    pub(super) addr: [u8; 16],
    pub(super) prefix: u8,
}

pub(super) const PERMIT_V4: [PermitV4; 7] = [
    PermitV4 {
        label: "loopback 127.0.0.0/8",
        addr: 0x7F00_0000,
        mask: 0xFF00_0000,
    },
    PermitV4 {
        label: "private 10.0.0.0/8",
        addr: 0x0A00_0000,
        mask: 0xFF00_0000,
    },
    PermitV4 {
        label: "private 172.16.0.0/12",
        addr: 0xAC10_0000,
        mask: 0xFFF0_0000,
    },
    PermitV4 {
        label: "private 192.168.0.0/16",
        addr: 0xC0A8_0000,
        mask: 0xFFFF_0000,
    },
    PermitV4 {
        label: "link-local 169.254.0.0/16",
        addr: 0xA9FE_0000,
        mask: 0xFFFF_0000,
    },
    PermitV4 {
        label: "cgnat 100.64.0.0/10",
        addr: 0x6440_0000,
        mask: 0xFFC0_0000,
    },
    PermitV4 {
        label: "local multicast 224.0.0.0/4",
        addr: 0xE000_0000,
        mask: 0xF000_0000,
    },
];

pub(super) const PERMIT_V6: [PermitV6; 4] = [
    PermitV6 {
        label: "loopback ::1/128",
        addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        prefix: 128,
    },
    PermitV6 {
        label: "link-local fe80::/10",
        addr: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 10,
    },
    PermitV6 {
        label: "unique-local fc00::/7",
        addr: [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 7,
    },
    PermitV6 {
        label: "local multicast ff00::/8",
        addr: [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 8,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rule {
    BlockAll(Layer),
    PermitV4(Layer, usize),
    PermitV6(Layer, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transition {
    Install,
    AlreadyActive,
}

pub(super) fn transition(active: bool) -> Transition {
    if active {
        Transition::AlreadyActive
    } else {
        Transition::Install
    }
}

pub(super) fn plan() -> Vec<Rule> {
    let mut rules = Vec::with_capacity(LAYERS.len() * (1 + PERMIT_V4.len() + PERMIT_V6.len()));
    for layer in LAYERS {
        rules.push(Rule::BlockAll(layer));
        if layer.is_ipv4() {
            for index in 0..PERMIT_V4.len() {
                rules.push(Rule::PermitV4(layer, index));
            }
        } else {
            for index in 0..PERMIT_V6.len() {
                rules.push(Rule::PermitV6(layer, index));
            }
        }
    }
    rules
}

pub(super) fn install<F>(rules: &[Rule], mut add: F) -> Result<Vec<u64>, (Vec<u64>, String)>
where
    F: FnMut(&Rule) -> Result<u64, String>,
{
    let mut installed = Vec::with_capacity(rules.len());
    for rule in rules {
        match add(rule) {
            Ok(id) => installed.push(id),
            Err(error) => return Err((installed, error)),
        }
    }
    Ok(installed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    Armed(Vec<u64>),
    RolledBack(Vec<u64>, String),
}

pub(super) fn run<F>(rules: &[Rule], add: F) -> Outcome
where
    F: FnMut(&Rule) -> Result<u64, String>,
{
    match install(rules, add) {
        Ok(ids) => Outcome::Armed(ids),
        Err((installed, error)) => Outcome::RolledBack(installed, error),
    }
}

#[cfg(test)]
pub(super) fn v4_matches(range: &PermitV4, address: u32) -> bool {
    address & range.mask == range.addr & range.mask
}

#[cfg(test)]
pub(super) fn v6_matches(range: &PermitV6, address: [u8; 16]) -> bool {
    let prefix = usize::from(range.prefix);
    let full_bytes = prefix / 8;
    if address[..full_bytes] != range.addr[..full_bytes] {
        return false;
    }
    let remainder = prefix % 8;
    if remainder == 0 {
        return true;
    }
    let bit_mask = 0xFFu8 << (8 - remainder);
    (address[full_bytes] & bit_mask) == (range.addr[full_bytes] & bit_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_matched(address: u32) -> Option<&'static str> {
        PERMIT_V4
            .iter()
            .find(|range| v4_matches(range, address))
            .map(|range| range.label)
    }

    fn v6_matched(address: [u8; 16]) -> Option<&'static str> {
        PERMIT_V6
            .iter()
            .find(|range| v6_matches(range, address))
            .map(|range| range.label)
    }

    #[test]
    fn permit_v4_table_has_two_permit_families_and_seven_ranges() {
        assert_eq!(PERMIT_V4.len(), 7, "seven IPv4 permit ranges");
        assert_eq!(PERMIT_V6.len(), 4, "four IPv6 permit ranges");
        for range in PERMIT_V4 {
            assert_eq!(
                range.addr & range.mask,
                range.addr,
                "{} must store the network address, not a host address",
                range.label
            );
            assert_ne!(range.mask, 0, "{} must not match everything", range.label);
            assert_ne!(
                range.mask,
                u32::MAX,
                "{} must not be a single-host range",
                range.label
            );
        }
    }

    #[test]
    fn permit_v4_masks_are_contiguous() {
        for range in PERMIT_V4 {
            let host_bits = !range.mask;
            assert_eq!(
                host_bits & host_bits.wrapping_add(1),
                0,
                "{} mask must be a contiguous prefix mask",
                range.label
            );
        }
    }

    #[test]
    fn permit_v4_covers_lan_and_loopback() {
        for (text, octets) in [
            ("127.0.0.1", [127u8, 0, 0, 1]),
            ("127.0.0.2", [127, 0, 0, 2]),
            ("10.5.5.5", [10, 5, 5, 5]),
            ("172.16.1.1", [172, 16, 1, 1]),
            ("172.31.255.254", [172, 31, 255, 254]),
            ("192.168.1.10", [192, 168, 1, 10]),
            ("169.254.10.10", [169, 254, 10, 10]),
            ("100.64.0.1", [100, 64, 0, 1]),
            ("100.127.255.255", [100, 127, 255, 255]),
            ("224.0.0.251", [224, 0, 0, 251]),
            ("239.255.255.250", [239, 255, 255, 250]),
        ] {
            assert!(
                v4_matched(u32::from_be_bytes(octets)).is_some(),
                "{text} must stay reachable during lockdown"
            );
        }
    }

    #[test]
    fn permit_v4_excludes_public_internet() {
        for (text, octets) in [
            ("8.8.8.8", [8u8, 8, 8, 8]),
            ("1.1.1.1", [1, 1, 1, 1]),
            ("9.9.9.9", [9, 9, 9, 9]),
            ("11.0.0.1", [11, 0, 0, 1]),
            ("172.32.0.1", [172, 32, 0, 1]),
            ("172.15.255.255", [172, 15, 255, 255]),
            ("100.128.0.1", [100, 128, 0, 1]),
            ("100.63.255.255", [100, 63, 255, 255]),
            ("169.255.0.1", [169, 255, 0, 1]),
            ("203.0.113.5", [203, 0, 113, 5]),
            ("223.255.255.255", [223, 255, 255, 255]),
            ("240.0.0.1", [240, 0, 0, 1]),
        ] {
            assert!(
                v4_matched(u32::from_be_bytes(octets)).is_none(),
                "{text} is internet traffic and must be blocked during lockdown"
            );
        }
    }

    #[test]
    fn permit_v6_covers_local_families_and_excludes_public() {
        let loopback = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut link_local = [0u8; 16];
        link_local[0] = 0xFE;
        link_local[1] = 0x80;
        link_local[15] = 1;
        let mut unique_local = [0u8; 16];
        unique_local[0] = 0xFD;
        unique_local[1] = 0x12;
        unique_local[15] = 1;
        let mut multicast = [0u8; 16];
        multicast[0] = 0xFF;
        multicast[1] = 0x02;
        multicast[15] = 0xFB;

        for address in [loopback, link_local, unique_local, multicast] {
            assert!(
                v6_matched(address).is_some(),
                "{address:?} must stay reachable during lockdown"
            );
        }

        let public = [
            0x20u8, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        assert!(v6_matched(public).is_none(), "global IPv6 must be blocked");
        let mut global_unicast = [0u8; 16];
        global_unicast[0] = 0x26;
        global_unicast[15] = 0x01;
        assert!(v6_matched(global_unicast).is_none());
        let mut just_above_loopback = [0u8; 16];
        just_above_loopback[15] = 2;
        assert!(v6_matched(just_above_loopback).is_none());
    }

    #[test]
    fn plan_blocks_first_then_permits_per_address_family() {
        let rules = plan();
        let expected = LAYERS.len() + 2 * PERMIT_V4.len() + 2 * PERMIT_V6.len();
        assert_eq!(rules.len(), expected);
        assert_eq!(rules.len(), 26);

        let mut cursor = 0usize;
        for layer in LAYERS {
            let permits = if layer.is_ipv4() {
                PERMIT_V4.len()
            } else {
                PERMIT_V6.len()
            };
            let group = &rules[cursor..cursor + 1 + permits];
            assert_eq!(
                group[0],
                Rule::BlockAll(layer),
                "{layer:?} block-all must be installed before its permits"
            );
            assert!(
                group[1..].iter().all(|rule| match rule {
                    Rule::PermitV4(owner, _) | Rule::PermitV6(owner, _) => *owner == layer,
                    Rule::BlockAll(_) => false,
                }),
                "{layer:?} permits must follow its own block-all rule"
            );
            cursor += 1 + permits;
        }
        assert_eq!(cursor, rules.len(), "the plan has no trailing rules");
    }

    #[test]
    fn plan_keeps_address_families_on_matching_layers() {
        for rule in plan() {
            match rule {
                Rule::BlockAll(_) => {}
                Rule::PermitV4(layer, index) => {
                    assert!(layer.is_ipv4(), "{layer:?} must not take an IPv4 permit");
                    assert!(index < PERMIT_V4.len());
                }
                Rule::PermitV6(layer, index) => {
                    assert!(!layer.is_ipv4(), "{layer:?} must not take an IPv6 permit");
                    assert!(index < PERMIT_V6.len());
                }
            }
        }
    }

    #[test]
    fn plan_covers_every_layer_and_ipv6_alongside_ipv4() {
        let rules = plan();
        for layer in LAYERS {
            let block_count = rules
                .iter()
                .filter(|rule| **rule == Rule::BlockAll(layer))
                .count();
            assert_eq!(block_count, 1, "{layer:?} needs exactly one block-all rule");
            let permit_count = rules
                .iter()
                .filter(|rule| match rule {
                    Rule::PermitV4(owner, _) | Rule::PermitV6(owner, _) => *owner == layer,
                    Rule::BlockAll(_) => false,
                })
                .count();
            let expected = if layer.is_ipv4() {
                PERMIT_V4.len()
            } else {
                PERMIT_V6.len()
            };
            assert_eq!(permit_count, expected, "{layer:?} permit count");
        }
        let ipv6_layers = LAYERS.iter().filter(|layer| !layer.is_ipv4()).count();
        assert_eq!(ipv6_layers, 2, "IPv6 must never be left open");
    }

    #[test]
    fn install_reports_every_installed_id() {
        let rules = plan();
        let total = rules.len();
        let result = install(&rules, |rule| Ok(total as u64 * 100 + rule_index(rule)));
        let ids = result.expect("all rules install");
        assert_eq!(ids.len(), total);
        assert!(ids.iter().all(|id| *id >= 100));
    }

    fn rule_index(rule: &Rule) -> u64 {
        match rule {
            Rule::BlockAll(_) => 0,
            Rule::PermitV4(_, index) => *index as u64,
            Rule::PermitV6(_, index) => *index as u64,
        }
    }

    #[test]
    fn install_returns_partial_state_for_rollback() {
        let rules = plan();
        let fail_at = 5usize;
        let result = install(&rules, |rule| {
            let position = rules
                .iter()
                .position(|candidate| candidate == rule)
                .unwrap();
            if position == fail_at {
                Err("simulated FwpmFilterAdd0 failure".to_string())
            } else {
                Ok(position as u64 + 1)
            }
        });
        let (installed, error) = result.expect_err("failure must surface");
        assert_eq!(
            installed.len(),
            fail_at,
            "rollback set holds only added ids"
        );
        assert_eq!(installed[0], 1);
        assert!(error.contains("simulated"));
    }

    #[test]
    fn install_propagates_first_error_without_installing_rest() {
        let rules = plan();
        let mut attempts = 0usize;
        let result = install(&rules, |_| {
            attempts += 1;
            Err(format!("boom {attempts}"))
        });
        let (installed, error) = result.expect_err("first rule already fails");
        assert!(installed.is_empty());
        assert_eq!(attempts, 1, "installation must stop at the first failure");
        assert_eq!(error, "boom 1");
    }

    #[test]
    fn install_with_no_rules_is_a_noop() {
        let ids = install(&[], |_| panic!("add must not be called")).expect("empty plan");
        assert!(ids.is_empty());
    }

    #[test]
    fn run_arms_with_every_id_when_all_filters_install() {
        let rules = plan();
        let total = rules.len();
        let outcome = run(&rules, |_| Ok(total as u64));
        match outcome {
            Outcome::Armed(ids) => assert_eq!(ids.len(), total),
            Outcome::RolledBack(_, error) => panic!("expected armed, got error {error}"),
        }
    }

    #[test]
    fn run_reports_the_rollback_set_and_the_error() {
        let rules = plan();
        let fail_at = 3usize;
        let mut seen = 0usize;
        let outcome = run(&rules, |_| {
            seen += 1;
            if seen > fail_at {
                Err(format!("filter {seen} rejected"))
            } else {
                Ok(seen as u64)
            }
        });
        match outcome {
            Outcome::RolledBack(installed, error) => {
                assert_eq!(
                    installed,
                    vec![1, 2, 3],
                    "rollback holds the added ids in order"
                );
                assert_eq!(error, "filter 4 rejected");
            }
            Outcome::Armed(ids) => panic!("expected rollback, armed with {ids:?}"),
        }
    }

    #[test]
    fn run_with_empty_plan_arms_nothing() {
        assert_eq!(
            run(&[], |_| panic!("never called")),
            Outcome::Armed(Vec::new())
        );
    }

    #[test]
    fn transition_only_installs_when_inactive() {
        assert_eq!(transition(false), Transition::Install);
        assert_eq!(transition(true), Transition::AlreadyActive);
    }

    #[test]
    fn permit_weight_outranks_block_weight() {
        let permit = u16::from(PERMIT_WEIGHT);
        let block = u16::from(BLOCK_WEIGHT);
        assert!(
            permit > block,
            "WFP applies the highest weight first, so permits must outrank block-all"
        );
        assert!(permit <= 15, "FWP_UINT8 weights are limited to 0..=15");
    }
}
