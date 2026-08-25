use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use browserd_egress::{CanonicalUrl, ConnectionPlanner, DnsResolution, EgressPolicy, PlanError};

fn url(input: &str) -> Option<CanonicalUrl> {
    let result = CanonicalUrl::parse(input);
    assert!(result.is_ok(), "test URL must be valid: {input}");
    result.ok()
}

#[test]
fn mixed_public_and_forbidden_dns_answers_fail_closed() {
    let planner = ConnectionPlanner::new(EgressPolicy::public_web_default());
    let Some(url) = url("https://example.com/resource") else {
        return;
    };
    let resolution = DnsResolution::new(
        "example.com",
        [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ],
    );

    assert!(matches!(
        planner.plan(&url, resolution),
        Err(PlanError::ForbiddenDnsCandidate { .. })
    ));
}

#[test]
fn allowlist_is_exact_declared_host_and_port_not_an_ip_allowlist() {
    let policy = EgressPolicy::allowlist_only(["allowed.example:443"]);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let planner = ConnectionPlanner::new(policy);
    let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    for allowed_url in [
        "https://allowed.example/path-a",
        "https://ALLOWED.EXAMPLE./path-b?query=opaque",
    ] {
        let Some(url) = url(allowed_url) else {
            continue;
        };
        assert!(
            planner
                .plan(&url, DnsResolution::new("allowed.example", [public_ip]))
                .is_ok(),
            "allowlisted authority was rejected: {allowed_url}",
        );
    }

    for blocked_url in [
        "https://sub.allowed.example/",
        "https://allowed.example:8443/",
        "https://not-allowed.example/",
    ] {
        let Some(url) = url(blocked_url) else {
            continue;
        };
        assert!(matches!(
            planner.plan(&url, DnsResolution::new(url.host(), [public_ip]),),
            Err(PlanError::HostNotAllowed { .. })
        ));
    }

    // Sharing the same public address with an allowed host must not authorize a
    // different declared CONNECT host.
    let Some(disallowed) = url("https://same-cdn.example/") else {
        return;
    };
    assert!(matches!(
        planner.plan(
            &disallowed,
            DnsResolution::new("same-cdn.example", [public_ip]),
        ),
        Err(PlanError::HostNotAllowed { .. })
    ));
}

#[test]
fn connect_plan_contains_the_inspected_sockaddr_and_preserves_hostname_semantics() {
    let planner = ConnectionPlanner::new(EgressPolicy::public_web_default());
    let Some(url) = url("https://service.example/api") else {
        return;
    };
    let selected_ip = Ipv4Addr::new(93, 184, 216, 34);
    let resolution = DnsResolution::new("service.example", [IpAddr::V4(selected_ip)]);

    let result = planner.plan(&url, resolution);
    assert!(result.is_ok());
    let Some(plan) = result.ok() else {
        return;
    };

    assert_eq!(
        plan.inspected_socket_addr().as_socket_addr(),
        SocketAddr::new(IpAddr::V4(selected_ip), 443),
    );
    assert_eq!(plan.declared_host(), "service.example");
    assert_eq!(plan.http_host_header(), "service.example");
    assert_eq!(plan.tls_server_name(), Some("service.example"));
}

#[test]
fn every_redirect_is_revalidated_from_scheme_through_connect_target() {
    let policy = EgressPolicy::allowlist_only([
        "start.example:443",
        "next.example:443",
        "metadata.example:443",
    ]);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let planner = ConnectionPlanner::new(policy);
    let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let Some(start) = url("https://start.example/") else {
        return;
    };
    let first = planner.plan(&start, DnsResolution::new("start.example", [public_ip]));
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };

    let Some(next) = url("https://next.example/landing") else {
        return;
    };
    assert!(
        planner
            .revalidate_redirect(
                &first,
                &next,
                DnsResolution::new("next.example", [public_ip]),
            )
            .is_ok()
    );

    let Some(disallowed_host) = url("https://outside.example/") else {
        return;
    };
    assert!(matches!(
        planner.revalidate_redirect(
            &first,
            &disallowed_host,
            DnsResolution::new("outside.example", [public_ip]),
        ),
        Err(PlanError::HostNotAllowed { .. })
    ));

    let Some(metadata) = url("https://metadata.example/latest/meta-data") else {
        return;
    };
    assert!(matches!(
        planner.revalidate_redirect(
            &first,
            &metadata,
            DnsResolution::new(
                "metadata.example",
                [IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            ),
        ),
        Err(PlanError::ForbiddenDnsCandidate { .. })
    ));

    let Some(file_redirect) = url("file:///etc/passwd") else {
        return;
    };
    assert!(matches!(
        planner.revalidate_redirect(
            &first,
            &file_redirect,
            DnsResolution::empty_for_local_scheme(),
        ),
        Err(PlanError::SchemeDenied { .. })
    ));
}
