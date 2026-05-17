use std::collections::HashMap;
use serde_json::{json, Value};

/// Detector signal input — matches the typed signal structure from detectors.
/// Defined locally to avoid cross-branch coupling during parallel development.
#[derive(Debug, Clone)]
pub struct DetectorSignal {
    pub detector: String,
    pub version: String,
    pub flag: bool,
    pub score: f64,
    pub metadata: HashMap<String, Value>,
}

/// PII signal — separate from ContentDetector signals because PII
/// engine has a different interface (scan_only vs scan_and_redact).
#[derive(Debug, Clone)]
pub struct PiiSignal {
    pub present: bool,
    pub types: Vec<String>,
    pub count: usize,
    pub version: String,
}

/// Control facts — the bridge between detector signals and Cedar.
/// Pure function output, no state, no IO.
pub struct ControlFacts {
    facts: HashMap<String, Value>,
}

impl ControlFacts {
    /// Map detector signals to control facts.
    /// O(n) over signals. No thresholds, no decisions.
    pub fn from_signals(signals: &[DetectorSignal], pii: Option<&PiiSignal>) -> Self {
        let mut facts = HashMap::new();
        for signal in signals {
            for (key, value) in map_signal(signal) {
                facts.insert(key, value);
            }
        }
        if let Some(pii) = pii {
            facts.insert("data_protection.pii_present".into(), json!(pii.present));
            facts.insert("data_protection.pii_types".into(), json!(pii.types));
            facts.insert("data_protection.pii_count".into(), json!(pii.count as i64));
        }
        Self { facts }
    }

    /// Get a fact by namespaced key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.facts.get(key)
    }

    /// Serialize to JSON for Cedar context injection.
    /// Builds nested structure: `{ "agent_integrity": { "injection_detected": true, ... }, ... }`
    pub fn to_cedar_context(&self) -> Value {
        let mut families: HashMap<String, HashMap<String, Value>> = HashMap::new();
        for (key, value) in &self.facts {
            if let Some((family, field)) = key.split_once('.') {
                families.entry(family.to_string())
                    .or_default()
                    .insert(field.to_string(), value.clone());
            }
        }
        json!(families)
    }

    /// Evidence labels for compliance queries.
    pub fn evidence_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        for key in self.facts.keys() {
            if let Some((family, _)) = key.split_once('.') {
                if !labels.contains(&family.to_string()) {
                    labels.push(family.to_string());
                }
            }
        }
        for (key, value) in &self.facts {
            if (key.ends_with("_detected") || key.ends_with("_present"))
                && value.as_bool() == Some(true)
            {
                if let Some((_, field)) = key.split_once('.') {
                        let detector_label = field
                            .trim_end_matches("_detected")
                            .trim_end_matches("_present");
                        if !labels.contains(&detector_label.to_string()) {
                            labels.push(detector_label.to_string());
                        }
                    }
            }
        }
        labels.sort();
        labels
    }

    /// All facts as a flat HashMap (for evidence entries).
    pub fn as_map(&self) -> &HashMap<String, Value> {
        &self.facts
    }
}

fn map_signal(signal: &DetectorSignal) -> Vec<(String, Value)> {
    match signal.detector.as_str() {
        "injection" => vec![
            ("agent_integrity.injection_detected".into(), json!(signal.flag)),
            ("agent_integrity.injection_score".into(), json!((signal.score * 100.0) as i64)),
            ("agent_integrity.injection_type".into(),
                json!(signal.metadata.get("type").unwrap_or(&json!("")))),
        ],
        "jailbreak" => vec![
            ("agent_integrity.jailbreak_detected".into(), json!(signal.flag)),
            ("agent_integrity.jailbreak_score".into(), json!((signal.score * 100.0) as i64)),
        ],
        "confidential" => vec![
            ("data_protection.confidential_detected".into(), json!(signal.flag)),
        ],
        "exfiltration" => vec![
            ("data_protection.exfiltration_detected".into(), json!(signal.flag)),
            ("data_protection.exfiltration_risk".into(), json!((signal.score * 100.0) as i64)),
            ("data_protection.exfiltration_url_count".into(),
                json!(signal.metadata.get("url_count").unwrap_or(&json!(0)))),
        ],
        "threat" => vec![
            ("content_safety.threat_detected".into(), json!(signal.flag)),
            ("content_safety.threat_score".into(), json!((signal.score * 100.0) as i64)),
        ],
        "toxicity" => vec![
            ("content_safety.toxicity_score".into(), json!((signal.score * 100.0) as i64)),
        ],
        "identity_claim" => vec![
            ("identity_safety.disclosure_detected".into(), json!(signal.flag)),
        ],
        "bias" => vec![
            ("content_safety.bias_detected".into(), json!(signal.flag)),
            ("content_safety.bias_score".into(), json!((signal.score * 100.0) as i64)),
        ],
        "tool_governance" => vec![
            ("tool_governance.unauthorized_detected".into(), json!(signal.flag)),
            // Note: unauthorized_tools and highest_risk are evidence-only fields for
            // audit trail forensics. They are NOT injected into the flat Cedar context
            // (which uses `unauthorized_tool_detected: bool` from ContextParams).
            // The nested ControlFacts::to_cedar_context() emits them but that path
            // is not used in the main evaluation pipeline.
            ("tool_governance.unauthorized_tools".into(),
                json!(signal.metadata.get("tool_names").unwrap_or(&json!([])))),
            ("tool_governance.highest_risk".into(),
                json!(signal.metadata.get("risk_category").unwrap_or(&json!("")))),
        ],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(detector: &str, flag: bool, score: f64) -> DetectorSignal {
        DetectorSignal {
            detector: detector.into(),
            version: "1.0".into(),
            flag,
            score,
            metadata: HashMap::new(),
        }
    }

    fn make_signal_with_meta(
        detector: &str,
        flag: bool,
        score: f64,
        metadata: HashMap<String, Value>,
    ) -> DetectorSignal {
        DetectorSignal {
            detector: detector.into(),
            version: "1.0".into(),
            flag,
            score,
            metadata,
        }
    }

    #[test]
    fn injection_maps_to_agent_integrity() {
        let mut meta = HashMap::new();
        meta.insert("type".into(), json!("indirect"));
        let signal = make_signal_with_meta("injection", true, 0.91, meta);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("agent_integrity.injection_detected"), Some(&json!(true)));
        assert_eq!(facts.get("agent_integrity.injection_score"), Some(&json!(91)));
        assert_eq!(facts.get("agent_integrity.injection_type"), Some(&json!("indirect")));
    }

    #[test]
    fn jailbreak_maps_to_agent_integrity() {
        let signal = make_signal("jailbreak", true, 0.85);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("agent_integrity.jailbreak_detected"), Some(&json!(true)));
        assert_eq!(facts.get("agent_integrity.jailbreak_score"), Some(&json!(85)));
    }

    #[test]
    fn confidential_maps_to_data_protection() {
        let signal = make_signal("confidential", true, 1.0);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("data_protection.confidential_detected"), Some(&json!(true)));
    }

    #[test]
    fn exfiltration_maps_to_data_protection() {
        let mut meta = HashMap::new();
        meta.insert("url_count".into(), json!(3));
        let signal = make_signal_with_meta("exfiltration", true, 0.72, meta);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("data_protection.exfiltration_detected"), Some(&json!(true)));
        assert_eq!(facts.get("data_protection.exfiltration_risk"), Some(&json!(72)));
        assert_eq!(facts.get("data_protection.exfiltration_url_count"), Some(&json!(3)));
    }

    #[test]
    fn threat_maps_to_content_safety() {
        let signal = make_signal("threat", true, 0.60);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("content_safety.threat_detected"), Some(&json!(true)));
        assert_eq!(facts.get("content_safety.threat_score"), Some(&json!(60)));
    }

    #[test]
    fn toxicity_maps_to_content_safety() {
        let signal = make_signal("toxicity", false, 0.45);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("content_safety.toxicity_score"), Some(&json!(45)));
    }

    #[test]
    fn identity_claim_maps_to_identity_safety() {
        let signal = make_signal("identity_claim", true, 1.0);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("identity_safety.disclosure_detected"), Some(&json!(true)));
    }

    #[test]
    fn tool_governance_maps_correctly() {
        let mut meta = HashMap::new();
        meta.insert("tool_names".into(), json!(["curl", "wget"]));
        meta.insert("risk_category".into(), json!("high"));
        let signal = make_signal_with_meta("tool_governance", true, 0.99, meta);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert_eq!(facts.get("tool_governance.unauthorized_detected"), Some(&json!(true)));
        assert_eq!(facts.get("tool_governance.unauthorized_tools"), Some(&json!(["curl", "wget"])));
        assert_eq!(facts.get("tool_governance.highest_risk"), Some(&json!("high")));
    }

    #[test]
    fn unknown_detector_produces_empty_facts() {
        let signal = make_signal("unknown_detector", true, 0.5);
        let facts = ControlFacts::from_signals(&[signal], None);

        assert!(facts.as_map().is_empty());
    }

    #[test]
    fn pii_signal_maps_correctly() {
        let pii = PiiSignal {
            present: true,
            types: vec!["email".into(), "ssn".into()],
            count: 4,
            version: "1.0".into(),
        };
        let facts = ControlFacts::from_signals(&[], Some(&pii));

        assert_eq!(facts.get("data_protection.pii_present"), Some(&json!(true)));
        assert_eq!(facts.get("data_protection.pii_types"), Some(&json!(["email", "ssn"])));
        assert_eq!(facts.get("data_protection.pii_count"), Some(&json!(4)));
    }

    #[test]
    fn to_cedar_context_produces_nested_json() {
        let signals = vec![
            make_signal("injection", true, 0.91),
            make_signal("threat", false, 0.30),
        ];
        let ctx = ControlFacts::from_signals(&signals, None).to_cedar_context();

        assert!(ctx.get("agent_integrity").is_some());
        assert_eq!(
            ctx["agent_integrity"]["injection_detected"],
            json!(true)
        );
        assert!(ctx.get("content_safety").is_some());
        assert_eq!(
            ctx["content_safety"]["threat_score"],
            json!(30)
        );
    }

    #[test]
    fn evidence_labels_returns_families_and_flagged_detectors() {
        let signals = vec![
            make_signal("injection", true, 0.9),
            make_signal("toxicity", false, 0.3),
        ];
        let labels = ControlFacts::from_signals(&signals, None).evidence_labels();

        assert!(labels.contains(&"agent_integrity".to_string()));
        assert!(labels.contains(&"content_safety".to_string()));
        // injection_detected=true → "injection" label
        assert!(labels.contains(&"injection".to_string()));
        // toxicity has no _detected/_present flag, so no extra label
    }

    #[test]
    fn empty_signals_produce_empty_facts() {
        let facts = ControlFacts::from_signals(&[], None);
        assert!(facts.as_map().is_empty());
        assert!(facts.evidence_labels().is_empty());
        assert_eq!(facts.to_cedar_context(), json!({}));
    }

    #[test]
    fn determinism_same_inputs_same_outputs() {
        let signals = vec![
            make_signal("injection", true, 0.91),
            make_signal("jailbreak", false, 0.10),
        ];
        let pii = PiiSignal {
            present: true,
            types: vec!["email".into()],
            count: 1,
            version: "1.0".into(),
        };

        let facts_a = ControlFacts::from_signals(&signals, Some(&pii));
        let facts_b = ControlFacts::from_signals(&signals, Some(&pii));

        assert_eq!(facts_a.as_map(), facts_b.as_map());
    }

    #[test]
    fn score_scaling_091_to_91() {
        let signal = make_signal("injection", true, 0.91);
        let facts = ControlFacts::from_signals(&[signal], None);
        assert_eq!(facts.get("agent_integrity.injection_score"), Some(&json!(91)));
    }

    #[test]
    fn score_scaling_boundary_values() {
        let zero = make_signal("threat", false, 0.0);
        let one = make_signal("jailbreak", true, 1.0);

        let facts_zero = ControlFacts::from_signals(&[zero], None);
        assert_eq!(facts_zero.get("content_safety.threat_score"), Some(&json!(0)));

        let facts_one = ControlFacts::from_signals(&[one], None);
        assert_eq!(facts_one.get("agent_integrity.jailbreak_score"), Some(&json!(100)));
    }

    #[test]
    fn every_known_detector_produces_at_least_one_fact() {
        let detectors = [
            "injection", "jailbreak", "confidential", "exfiltration",
            "threat", "toxicity", "identity_claim", "bias", "tool_governance",
        ];
        for name in detectors {
            let signal = make_signal(name, true, 0.5);
            let facts = ControlFacts::from_signals(&[signal], None);
            assert!(
                !facts.as_map().is_empty(),
                "detector '{}' should produce at least one fact",
                name
            );
        }
    }

    #[test]
    fn multiple_signals_combined() {
        let signals = vec![
            make_signal("injection", true, 0.9),
            make_signal("threat", true, 0.8),
            make_signal("toxicity", false, 0.3),
        ];
        let pii = PiiSignal {
            present: true,
            types: vec!["phone".into()],
            count: 2,
            version: "1.0".into(),
        };
        let facts = ControlFacts::from_signals(&signals, Some(&pii));

        // All families present
        assert!(facts.get("agent_integrity.injection_detected").is_some());
        assert!(facts.get("content_safety.threat_detected").is_some());
        assert!(facts.get("content_safety.toxicity_score").is_some());
        assert!(facts.get("data_protection.pii_present").is_some());
    }
}
