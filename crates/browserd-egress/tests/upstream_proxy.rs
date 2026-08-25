use browserd_egress::{NetworkClass, UpstreamProxy, UpstreamProxyError, UpstreamProxyPolicy};

#[test]
fn shared_public_tier_rejects_arbitrary_tenant_upstream_proxy() {
    assert_eq!(
        UpstreamProxyPolicy::validate(
            NetworkClass::SharedPublic,
            &UpstreamProxy::TenantProvided {
                endpoint: "http://tenant-proxy.example:3128".to_owned(),
            },
        ),
        Err(UpstreamProxyError::TenantProxyForbiddenInSharedTier),
    );
}

#[test]
fn shared_public_tier_only_accepts_browserd_managed_or_approved_routes() {
    for proxy in [
        UpstreamProxy::BrowserdManagedRegional {
            route_id: "region-ap-northeast".to_owned(),
        },
        UpstreamProxy::ApprovedCorporate {
            policy_id: "approved-corporate-policy".to_owned(),
        },
    ] {
        assert_eq!(
            UpstreamProxyPolicy::validate(NetworkClass::SharedPublic, &proxy),
            Ok(()),
        );
    }
}

#[test]
fn tenant_proxy_requires_a_dedicated_private_network_class() {
    let proxy = UpstreamProxy::TenantProvided {
        endpoint: "http://tenant-proxy.internal:3128".to_owned(),
    };

    assert_eq!(
        UpstreamProxyPolicy::validate(NetworkClass::DedicatedPrivate, &proxy),
        Ok(()),
    );
}
