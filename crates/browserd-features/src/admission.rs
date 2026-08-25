use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionClass {
    Pdf,
    FullPageScreenshot,
    LargeSnapshot,
    Scrape,
}

impl AdmissionClass {
    const fn index(self) -> usize {
        match self {
            Self::Pdf => 0,
            Self::FullPageScreenshot => 1,
            Self::LargeSnapshot => 2,
            Self::Scrape => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureConcurrencyLimits {
    pub pdf: u32,
    pub full_page_screenshot: u32,
    pub large_snapshot: u32,
    pub scrape: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Disabled,
    AtCapacity,
    StateUnavailable,
    CounterOverflow,
}

#[derive(Debug)]
struct AdmissionState {
    limits: [u32; 4],
    in_use: [u32; 4],
}

#[derive(Clone, Debug)]
pub struct FeatureAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

impl FeatureAdmission {
    #[must_use]
    pub fn new(limits: FeatureConcurrencyLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState {
                limits: [
                    limits.pdf,
                    limits.full_page_screenshot,
                    limits.large_snapshot,
                    limits.scrape,
                ],
                in_use: [0; 4],
            })),
        }
    }

    pub fn acquire(&self, class: AdmissionClass) -> Result<AdmissionPermit, AdmissionError> {
        let index = class.index();
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdmissionError::StateUnavailable)?;
        let limit = state.limits[index];
        if limit == 0 {
            return Err(AdmissionError::Disabled);
        }
        if state.in_use[index] >= limit {
            return Err(AdmissionError::AtCapacity);
        }
        state.in_use[index] = state.in_use[index]
            .checked_add(1)
            .ok_or(AdmissionError::CounterOverflow)?;
        drop(state);
        Ok(AdmissionPermit {
            state: self.state.clone(),
            class,
            live: true,
        })
    }

    #[must_use]
    pub fn in_use(&self, class: AdmissionClass) -> u32 {
        lock(&self.state).in_use[class.index()]
    }
}

pub struct AdmissionPermit {
    state: Arc<Mutex<AdmissionState>>,
    class: AdmissionClass,
    live: bool,
}

impl fmt::Debug for AdmissionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionPermit")
            .field("class", &self.class)
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

impl PartialEq for AdmissionPermit {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
            && self.class == other.class
            && self.live == other.live
    }
}

impl Eq for AdmissionPermit {}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let index = self.class.index();
        let mut state = lock(&self.state);
        state.in_use[index] = state.in_use[index].saturating_sub(1);
        self.live = false;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
