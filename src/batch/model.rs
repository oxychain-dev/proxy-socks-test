use super::{ProxyProtocol, ProxySpec};
use anyhow::{anyhow, Result};
use std::{fmt, net::IpAddr, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestProfile {
    Basic,
    Standard,
    Full,
}

impl TestProfile {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            _ => Err(anyhow!("unsupported test profile: {value}")),
        }
    }

    pub(super) fn includes_stage(self, stage: u8) -> bool {
        match self {
            Self::Basic => stage <= 3,
            Self::Standard => stage <= 4,
            Self::Full => stage <= 6,
        }
    }
}

impl fmt::Display for TestProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Basic => "basic",
            Self::Standard => "standard",
            Self::Full => "full",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StageStatus {
    Pass,
    Partial,
    Fail,
    Skip,
}

impl StageStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Partial => "partial",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct StageResult {
    pub(super) stage: u8,
    pub(super) name: &'static str,
    pub(super) status: StageStatus,
    pub(super) duration_ms: Option<u128>,
    pub(super) error: Option<String>,
}

impl StageResult {
    pub(super) fn pass(stage: u8, name: &'static str, duration: Duration) -> Self {
        Self {
            stage,
            name,
            status: StageStatus::Pass,
            duration_ms: Some(duration.as_millis()),
            error: None,
        }
    }

    pub(super) fn partial(
        stage: u8, name: &'static str, duration: Duration, error: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            name,
            status: StageStatus::Partial,
            duration_ms: Some(duration.as_millis()),
            error: Some(error.into()),
        }
    }

    pub(super) fn fail(
        stage: u8, name: &'static str, duration: Duration, error: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            name,
            status: StageStatus::Fail,
            duration_ms: Some(duration.as_millis()),
            error: Some(error.into()),
        }
    }

    pub(super) fn skip(stage: u8, name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            stage,
            name,
            status: StageStatus::Skip,
            duration_ms: None,
            error: Some(reason.into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct IpMetadata {
    pub(super) raw_json: String,
    pub(super) country: Option<String>,
    pub(super) region: Option<String>,
    pub(super) city: Option<String>,
    pub(super) organization: Option<String>,
    pub(super) asn: Option<String>,
    pub(super) timezone: Option<String>,
}

#[derive(Debug)]
pub(super) struct ProbeMetrics {
    pub(super) protocol: ProxyProtocol,
    pub(super) validation_latency_ms: u128,
    pub(super) exit_ip: IpAddr,
    pub(super) latency_samples_ms: Vec<u128>,
    pub(super) latency_p50_ms: Option<f64>,
    pub(super) latency_p95_ms: Option<f64>,
    pub(super) jitter_ms: Option<f64>,
    pub(super) download_mbps: Option<f64>,
    pub(super) upload_mbps: Option<f64>,
    pub(super) exit_ip_changed: bool,
    pub(super) exit_ip_info: Option<IpMetadata>,
}

#[derive(Debug)]
pub(super) struct BatchResult {
    pub(super) proxy: ProxySpec,
    pub(super) resolved_ips: Vec<IpAddr>,
    pub(super) tested_ip: Option<IpAddr>,
    pub(super) reverse_dns: Option<String>,
    pub(super) endpoint_connect_ms: Option<u128>,
    pub(super) endpoint_ip_info: Option<IpMetadata>,
    pub(super) metrics: Option<ProbeMetrics>,
    pub(super) stages: Vec<StageResult>,
    pub(super) error: Option<String>,
}

impl BatchResult {
    pub(super) fn valid(&self) -> bool {
        self.metrics.is_some()
    }

    pub(super) fn stage_failure_labels(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.stages
            .iter()
            .filter(|stage| matches!(stage.status, StageStatus::Fail))
            .map(|stage| stage.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_gate_expected_stages() {
        assert!(TestProfile::Basic.includes_stage(3));
        assert!(!TestProfile::Basic.includes_stage(4));
        assert!(TestProfile::Standard.includes_stage(4));
        assert!(!TestProfile::Standard.includes_stage(5));
        assert!(TestProfile::Full.includes_stage(6));
    }
}
