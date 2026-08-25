use browserd_egress::{CanonicalUrl, NavigationScope, SchemeDecision, SchemePolicy};

#[test]
fn top_level_skills_only_send_http_and_https_to_egress() {
    let policy = SchemePolicy::browserd_default();

    for scheme in ["http", "https"] {
        assert_eq!(
            policy.classify(NavigationScope::TopLevelSkill, scheme),
            SchemeDecision::AllowEgress,
        );
    }

    for scheme in [
        "ws",
        "wss",
        "data",
        "blob",
        "file",
        "chrome",
        "devtools",
        "filesystem",
        "javascript",
        "view-source",
        "intent",
        "tenant-custom",
    ] {
        assert_eq!(
            policy.classify(NavigationScope::TopLevelSkill, scheme),
            SchemeDecision::Deny,
            "unexpected top-level decision for {scheme}",
        );
    }
}

#[test]
fn page_requests_only_send_network_schemes_to_egress() {
    let policy = SchemePolicy::browserd_default();

    for scheme in ["http", "https", "ws", "wss"] {
        assert_eq!(
            policy.classify(NavigationScope::PageRequest, scheme),
            SchemeDecision::AllowEgress,
        );
    }

    for scheme in ["data", "blob"] {
        assert_eq!(
            policy.classify(NavigationScope::PageRequest, scheme),
            SchemeDecision::AllowLocalOnly,
            "{scheme} must never result in an egress connection",
        );
    }

    for scheme in [
        "file",
        "chrome",
        "devtools",
        "filesystem",
        "javascript",
        "view-source",
        "intent",
        "tenant-custom",
    ] {
        assert_eq!(
            policy.classify(NavigationScope::PageRequest, scheme),
            SchemeDecision::Deny,
            "unexpected page decision for {scheme}",
        );
    }
}

#[test]
fn canonical_url_normalizes_authority_before_policy_checks() {
    let result = CanonicalUrl::parse("HTTP://ExAmPlE.COM.:80/a/../resource?x=1#fragment");
    assert!(result.is_ok());
    let Some(url) = result.ok() else {
        return;
    };

    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host(), "example.com");
    assert_eq!(url.port(), 80);
    assert_eq!(url.path_and_query(), "/resource?x=1");
}

#[test]
fn canonical_url_applies_idna_and_normalizes_legacy_ipv4_forms() {
    let idna = CanonicalUrl::parse("https://bücher.example/");
    assert!(idna.is_ok());
    let Some(idna) = idna.ok() else {
        return;
    };
    assert_eq!(idna.host(), "xn--bcher-kva.example");

    for input in [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ] {
        let result = CanonicalUrl::parse(input);
        assert!(
            result.is_ok(),
            "legacy IPv4 input was not recognized: {input}"
        );
        let Some(url) = result.ok() else {
            continue;
        };
        assert_eq!(url.host(), "127.0.0.1", "input was {input}");
    }
}

#[test]
fn canonical_url_applies_uts46_mapping_and_unicode_normalization() {
    for (input, expected_host) in [
        ("https://ＥＸＡＭＰＬＥ．ＣＯＭ/", "example.com"),
        ("https://bu\u{0308}cher.example/", "xn--bcher-kva.example"),
        ("https://faß.de/", "xn--fa-hia.de"),
    ] {
        let parsed = CanonicalUrl::parse(input);
        assert!(parsed.is_ok(), "UTS #46 input was rejected: {input}");
        let Some(parsed) = parsed.ok() else {
            continue;
        };
        assert_eq!(parsed.host(), expected_host, "input was {input}");
    }
}

#[test]
fn canonical_url_rejects_ambiguous_or_credential_bearing_authorities() {
    for input in [
        "https://user:password@example.com/",
        "https://example.com%2e/",
        "https://example.com:4%34%33/",
        "https://[fe80::1%25eth0]/",
        "https://[fe80::1%eth0]/",
    ] {
        assert!(
            CanonicalUrl::parse(input).is_err(),
            "ambiguous authority must be rejected: {input}",
        );
    }
}
