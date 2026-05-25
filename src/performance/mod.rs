pub mod models;

use crate::performance::models::PerformanceSample;

pub trait PerformanceProvider: Send + Sync {
    fn record(&self, sample: PerformanceSample);
}

/// No-op stub for open-core builds.
pub struct NoopPerformance;

impl PerformanceProvider for NoopPerformance {
    fn record(&self, _sample: PerformanceSample) {}
}

/// Trait for anomaly detection state. Implemented by steer-ee's AnomalyState.
pub trait AnomalyProvider: Send + Sync {
    fn is_anomalous(&self) -> bool;
    fn anomaly_type(&self) -> String;
}

/// No-op stub — never anomalous in open-core.
pub struct NoopAnomaly;

impl AnomalyProvider for NoopAnomaly {
    fn is_anomalous(&self) -> bool {
        false
    }
    fn anomaly_type(&self) -> String {
        String::new()
    }
}
