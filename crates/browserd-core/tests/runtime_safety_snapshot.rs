#![allow(clippy::expect_used)]
use browserd_core::{SafetySwitchMutation, SafetySwitchSnapshot};
use serde_json::json;
use std::net::IpAddr;

#[test]
fn strict_wire_cannot_bypass_bounds_or_canonical_rules() {
    let valid = serde_json::to_value(SafetySwitchSnapshot::default()).expect("baseline");
    for (field, value) in [
        ("version", json!(u64::MAX)),
        ("max_contexts_per_shard", json!(0)),
        ("max_targets_per_session", json!(129)),
        ("unknown", json!(true)),
        ("disabled_chromium_builds", json!(["NOT-A-DIGEST"])),
        ("denied_domains", json!(["EXAMPLE.TEST"])),
        ("denied_domains", json!(["127.0.0.1"])),
        ("denied_ips", json!(["::ffff:192.0.2.1"])),
        ("stopped_network_classes", json!(["public web"])),
    ] {
        let mut wire = valid.clone();
        wire[field] = value;
        assert!(
            serde_json::from_value::<SafetySwitchSnapshot>(wire).is_err(),
            "{field}"
        );
    }
    let mut wire = valid;
    wire["denied_domains"] = json!(
        (0..1025)
            .map(|i| format!("host{i}.test"))
            .collect::<Vec<_>>()
    );
    assert!(serde_json::from_value::<SafetySwitchSnapshot>(wire).is_err());
}

#[test]
fn canonical_reducer_binds_digest_and_normalizes_domain_and_mapped_ip() {
    let initial = SafetySwitchSnapshot::default();
    let alias = SafetySwitchMutation::SetDeniedDomain {
        domain: " EXAMPLE.TEST. ".to_owned(),
        denied: true,
    };
    let canonical = alias.canonicalized().expect("canonical");
    let changed = initial.apply(&alias).expect("change");
    assert_eq!(
        changed,
        initial.apply(&canonical).expect("same canonical body")
    );
    assert_eq!(changed.version(), 1);
    assert_eq!(initial.version(), 0);
    assert!(changed.domain_denied("a.example.test"));
    assert!(!changed.domain_denied("notexample.test"));
    let mapped: IpAddr = "::ffff:192.0.2.1".parse().expect("mapped");
    let changed = changed
        .apply(&SafetySwitchMutation::SetDeniedIp {
            ip: mapped,
            denied: true,
        })
        .expect("IP");
    assert!(changed.ip_denied(mapped));
    assert!(changed.ip_denied("192.0.2.1".parse().expect("IPv4")));
    let round_trip: SafetySwitchSnapshot =
        serde_json::from_slice(&serde_json::to_vec(&changed).expect("encode")).expect("validate");
    assert_eq!(
        round_trip.digest().expect("digest"),
        changed.digest().expect("original")
    );
    assert!(
        serde_json::from_value::<SafetySwitchMutation>(
            json!({"type":"disable_downloads","value":true,"unexpected":false})
        )
        .is_err()
    );
}

#[test]
fn runtime_intents_cannot_manufacture_local_shared_qualification() {
    let initial = SafetySwitchSnapshot::default();
    let allowed = initial
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent");
    let allowed = allowed
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("density");
    assert!(!allowed.shared_context_qualified());
    assert!(!allowed.shared_context_admission_allowed());
    assert!(SafetySwitchMutation::SetForceDedicatedProcess(false).is_runtime_mutation());
    assert!(
        !SafetySwitchMutation::SetSharedAdmission {
            qualified: true,
            force_dedicated_process: false,
            max_contexts_per_shard: 4
        }
        .is_runtime_mutation()
    );
}
