use std::fmt;
use std::time::Duration;

const KIB: u64 = 1_024;
const MIB: u64 = 1_024 * KIB;
const GIB: u64 = 1_024 * MIB;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeLimits {
    pub session: SessionLimits,
    pub action: ActionLimits,
    pub memory: MemoryLimits,
    pub artifact: ArtifactLimits,
    pub viewer: ViewerLimits,
    pub snapshot: SnapshotLimits,
}

impl RuntimeLimits {
    pub fn validate(&self) -> Result<(), ResourceValidationError> {
        if self.memory.soft_shard.absolute_bytes >= self.memory.hard_shard.absolute_bytes
            || self.memory.soft_shard.budget_percent >= self.memory.hard_shard.budget_percent
        {
            return Err(ResourceValidationError::SoftMemoryNotBelowHard);
        }
        if self.session.max_pages_per_session > self.session.max_pages_per_shard {
            return Err(ResourceValidationError::SessionPagesExceedShard);
        }
        if self.session.max_targets_per_session > self.session.max_targets_per_shard {
            return Err(ResourceValidationError::SessionTargetsExceedShard);
        }
        if !(1..=2).contains(&self.viewer.frame_queue_capacity) {
            return Err(ResourceValidationError::ViewerFrameQueueOutOfRange);
        }
        if self.memory.soft_shard.budget_percent == 0
            || self.memory.hard_shard.budget_percent > 100
            || self.memory.soft_shard.absolute_bytes == 0
            || self.memory.hard_shard.absolute_bytes == 0
        {
            return Err(ResourceValidationError::InvalidMemoryThreshold);
        }
        if self.session.max_contexts_per_shard == 0
            || self.session.max_pages_per_session == 0
            || self.session.max_pages_per_shard == 0
            || self.session.max_targets_per_session == 0
            || self.session.max_targets_per_shard == 0
        {
            return Err(ResourceValidationError::ZeroCapacityLimit);
        }
        if self.viewer.jpeg_quality > 100
            || self.viewer.target_fps == 0
            || self.viewer.rendered_width == 0
            || self.viewer.rendered_height == 0
        {
            return Err(ResourceValidationError::InvalidViewerLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    pub max_contexts_per_shard: u32,
    pub max_pages_per_session: u32,
    pub max_pages_per_shard: u32,
    pub max_frames_per_session: u32,
    pub max_workers_per_session: u32,
    pub max_service_workers_per_session: u32,
    pub max_targets_per_session: u32,
    pub max_targets_per_shard: u32,
    pub max_target_creations_per_10s: u32,
    pub default_ttl: Duration,
    pub default_idle_timeout: Duration,
    pub create_operation_deadline: Duration,
    pub browser_max_age: Duration,
    pub max_contexts_per_browser_lifetime: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_contexts_per_shard: 8,
            max_pages_per_session: 8,
            max_pages_per_shard: 32,
            max_frames_per_session: 64,
            max_workers_per_session: 16,
            max_service_workers_per_session: 8,
            max_targets_per_session: 96,
            max_targets_per_shard: 256,
            max_target_creations_per_10s: 64,
            default_ttl: Duration::from_secs(30 * 60),
            default_idle_timeout: Duration::from_secs(10 * 60),
            create_operation_deadline: Duration::from_secs(30),
            browser_max_age: Duration::from_secs(2 * 60 * 60),
            max_contexts_per_browser_lifetime: 500,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionLimits {
    pub default_execution_timeout: Duration,
    pub navigation_execution_timeout: Duration,
    pub pdf_scrape_execution_timeout: Duration,
    pub max_evaluate_source_bytes: u64,
    pub max_evaluate_result_bytes: u64,
    pub max_selector_bytes: u64,
    pub max_pending_actions_per_session: u32,
}

impl Default for ActionLimits {
    fn default() -> Self {
        Self {
            default_execution_timeout: Duration::from_secs(30),
            navigation_execution_timeout: Duration::from_secs(45),
            pdf_scrape_execution_timeout: Duration::from_secs(60),
            max_evaluate_source_bytes: 64 * KIB,
            max_evaluate_result_bytes: MIB,
            max_selector_bytes: 8 * KIB,
            max_pending_actions_per_session: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryThreshold {
    pub absolute_bytes: u64,
    pub budget_percent: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryLimits {
    pub soft_shard: MemoryThreshold,
    pub hard_shard: MemoryThreshold,
    pub oom_group: bool,
    pub private_dev_shm_bytes: u64,
    pub profile_temp_filesystem_bytes: u64,
    pub rlimit_core_bytes: u64,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            soft_shard: MemoryThreshold {
                absolute_bytes: 5 * GIB / 2,
                budget_percent: 70,
            },
            hard_shard: MemoryThreshold {
                absolute_bytes: 7 * GIB / 2,
                budget_percent: 90,
            },
            oom_group: true,
            private_dev_shm_bytes: 512 * MIB,
            profile_temp_filesystem_bytes: 2 * GIB,
            rlimit_core_bytes: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactLimits {
    pub max_upload_file_bytes: u64,
    pub max_download_file_bytes: u64,
    pub max_committed_bytes_per_session: u64,
    pub max_in_flight_bytes_per_session: u64,
    pub max_screenshot_width: u32,
    pub max_screenshot_height: u32,
    pub max_inline_snapshot_screenshot_bytes: u64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_upload_file_bytes: 50 * MIB,
            max_download_file_bytes: 100 * MIB,
            max_committed_bytes_per_session: 500 * MIB,
            max_in_flight_bytes_per_session: 128 * MIB,
            max_screenshot_width: 1_920,
            max_screenshot_height: 1_080,
            max_inline_snapshot_screenshot_bytes: 512 * KIB,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerLimits {
    pub target_fps: u32,
    pub jpeg_quality: u8,
    pub rendered_width: u32,
    pub rendered_height: u32,
    pub frame_queue_capacity: usize,
    pub control_lease: Duration,
    pub max_observers_per_session: u32,
    pub max_input_messages_per_10s: u32,
}

impl Default for ViewerLimits {
    fn default() -> Self {
        Self {
            target_fps: 12,
            jpeg_quality: 70,
            rendered_width: 1_920,
            rendered_height: 1_080,
            frame_queue_capacity: 2,
            control_lease: Duration::from_secs(60),
            max_observers_per_session: 4,
            max_input_messages_per_10s: 240,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotLimits {
    pub max_nodes: u32,
    pub max_string_bytes_per_node: u64,
    pub max_result_bytes: u64,
    pub max_generation_time: Duration,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_nodes: 3_000,
            max_string_bytes_per_node: 4 * KIB,
            max_result_bytes: 4 * MIB,
            max_generation_time: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ActionResourceClass {
    #[default]
    Lightweight,
    Interactive,
    Heavy,
    Pdf,
    FullPageScreenshot,
    LargeSnapshot,
    ArtifactFinalization,
    ViewerEncoding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRequest {
    pub context_slots: u32,
    pub memory_reservation_bytes: u64,
    pub page_slots: u32,
    pub target_slots: u32,
    pub viewer_slots: u32,
    pub process_slots: u32,
    pub action_class: ActionResourceClass,
}

impl ResourceRequest {
    pub fn validate_against(&self, limits: &RuntimeLimits) -> Result<(), ResourceValidationError> {
        limits.validate()?;
        if self.context_slots == 0 || self.context_slots > limits.session.max_contexts_per_shard {
            return Err(ResourceValidationError::ContextSlotsExceeded);
        }
        if self.page_slots > limits.session.max_pages_per_session {
            return Err(ResourceValidationError::PageSlotsExceeded);
        }
        if self.target_slots > limits.session.max_targets_per_session {
            return Err(ResourceValidationError::TargetSlotsExceeded);
        }
        if self.viewer_slots > limits.viewer.max_observers_per_session {
            return Err(ResourceValidationError::ViewerSlotsExceeded);
        }
        if self.memory_reservation_bytes > limits.memory.hard_shard.absolute_bytes {
            return Err(ResourceValidationError::MemoryReservationExceeded);
        }
        if self.process_slots > 1 {
            return Err(ResourceValidationError::ProcessSlotsExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceValidationError {
    SoftMemoryNotBelowHard,
    SessionPagesExceedShard,
    SessionTargetsExceedShard,
    ViewerFrameQueueOutOfRange,
    InvalidMemoryThreshold,
    ZeroCapacityLimit,
    InvalidViewerLimit,
    ContextSlotsExceeded,
    PageSlotsExceeded,
    TargetSlotsExceeded,
    ViewerSlotsExceeded,
    MemoryReservationExceeded,
    ProcessSlotsExceeded,
}

impl fmt::Display for ResourceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SoftMemoryNotBelowHard => "soft memory limit must be below hard memory limit",
            Self::SessionPagesExceedShard => "session page limit exceeds shard page limit",
            Self::SessionTargetsExceedShard => "session target limit exceeds shard target limit",
            Self::ViewerFrameQueueOutOfRange => "viewer frame queue must contain one or two frames",
            Self::InvalidMemoryThreshold => "memory threshold is invalid",
            Self::ZeroCapacityLimit => "capacity limits must be nonzero",
            Self::InvalidViewerLimit => "viewer limits are invalid",
            Self::ContextSlotsExceeded => "context slot request exceeds configured capacity",
            Self::PageSlotsExceeded => "page slot request exceeds configured capacity",
            Self::TargetSlotsExceeded => "target slot request exceeds configured capacity",
            Self::ViewerSlotsExceeded => "viewer slot request exceeds configured capacity",
            Self::MemoryReservationExceeded => "memory reservation exceeds configured hard limit",
            Self::ProcessSlotsExceeded => "process slot request exceeds session capacity",
        })
    }
}

impl std::error::Error for ResourceValidationError {}
