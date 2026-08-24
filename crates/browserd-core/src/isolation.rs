#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IsolationProfile {
    SharedContext,
    TenantDedicatedShard,
    DedicatedProcess,
    DedicatedWorker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationEscalation {
    None,
    TenantDedicatedShard,
    DedicatedProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationPolicy {
    minimum_profile: IsolationProfile,
    force_dedicated_process: bool,
}

impl IsolationPolicy {
    #[must_use]
    pub const fn new(minimum_profile: IsolationProfile, force_dedicated_process: bool) -> Self {
        Self {
            minimum_profile,
            force_dedicated_process,
        }
    }

    #[must_use]
    pub fn decide(
        &self,
        requested: IsolationProfile,
        escalation: IsolationEscalation,
    ) -> IsolationDecision {
        let escalation_minimum = match escalation {
            IsolationEscalation::None => IsolationProfile::SharedContext,
            IsolationEscalation::TenantDedicatedShard => IsolationProfile::TenantDedicatedShard,
            IsolationEscalation::DedicatedProcess => IsolationProfile::DedicatedProcess,
        };
        let mut effective_profile = requested.max(self.minimum_profile).max(escalation_minimum);

        if self.force_dedicated_process && effective_profile != IsolationProfile::DedicatedWorker {
            effective_profile = effective_profile.max(IsolationProfile::DedicatedProcess);
        }

        IsolationDecision {
            effective_profile,
            single_session_per_chromium: self.force_dedicated_process
                || effective_profile == IsolationProfile::DedicatedProcess,
        }
    }

    #[must_use]
    pub const fn minimum_profile(self) -> IsolationProfile {
        self.minimum_profile
    }

    #[must_use]
    pub const fn force_dedicated_process(self) -> bool {
        self.force_dedicated_process
    }
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self::new(IsolationProfile::SharedContext, false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationDecision {
    effective_profile: IsolationProfile,
    single_session_per_chromium: bool,
}

impl IsolationDecision {
    #[must_use]
    pub const fn effective_profile(self) -> IsolationProfile {
        self.effective_profile
    }

    #[must_use]
    pub const fn single_session_per_chromium(self) -> bool {
        self.single_session_per_chromium
    }
}
