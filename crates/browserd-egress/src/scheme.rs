/// The origin of a URL decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationScope {
    /// A URL supplied directly to a browserd Skill.
    TopLevelSkill,
    /// A request initiated by a page.
    PageRequest,
}

/// Whether a scheme may create an egress connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemeDecision {
    /// The request may be passed to the mandatory egress path.
    AllowEgress,
    /// The browser may handle the URL locally, but it must not reach egress.
    AllowLocalOnly,
    /// The URL is forbidden.
    Deny,
}

/// Browserd's fixed scheme policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchemePolicy;

impl SchemePolicy {
    /// Returns the standard v1 policy.
    #[must_use]
    pub const fn browserd_default() -> Self {
        Self
    }

    /// Classifies a scheme without trusting its casing.
    #[must_use]
    pub fn classify(self, scope: NavigationScope, scheme: &str) -> SchemeDecision {
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            return SchemeDecision::AllowEgress;
        }

        match scope {
            NavigationScope::TopLevelSkill => SchemeDecision::Deny,
            NavigationScope::PageRequest => {
                if scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss") {
                    SchemeDecision::AllowEgress
                } else if scheme.eq_ignore_ascii_case("data") || scheme.eq_ignore_ascii_case("blob")
                {
                    SchemeDecision::AllowLocalOnly
                } else {
                    SchemeDecision::Deny
                }
            }
        }
    }
}
