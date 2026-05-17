//! Confidential content detector (Tier 2 — regex hot path).
//!
//! Detects classification labels, NDA markers, and confidentiality
//! notices in LLM responses. Maps to AIUC-1 control S8 (confidential block).

use once_cell::sync::Lazy;
use regex::RegexSet;
use crate::detectors::{ContentDetector, DetectionResult, DetectorFinding, truncate_match};
// DetectorSignal and HashMap not needed — uses default signal() impl

static PATTERN_META: Lazy<Vec<(&str, &str)>> = Lazy::new(|| vec![
    // Classification labels
    ("confidential_tag", "classification_label"),
    ("internal_only_tag", "classification_label"),
    ("top_secret_tag", "classification_label"),
    ("restricted_tag", "classification_label"),
    ("secret_tag", "classification_label"),
    ("proprietary_tag", "classification_label"),
    // NDA markers
    ("nda_reference", "nda_marker"),
    ("non_disclosure", "nda_marker"),
    // Document controls
    ("do_not_distribute", "distribution_control"),
    ("not_for_release", "distribution_control"),
    ("eyes_only", "distribution_control"),
    ("need_to_know", "distribution_control"),
    // Data sensitivity
    ("pci_dss_data", "data_sensitivity"),
    ("hipaa_phi", "data_sensitivity"),
]);

static PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec![
    // Classification labels (bracketed and standalone)
    r"(?i)\[?\s*CONFIDENTIAL\s*\]?",
    r"(?i)\[?\s*INTERNAL(\s+ONLY|\s+USE)?\s*\]?",
    r"(?i)\[?\s*TOP\s+SECRET\s*\]?",
    r"(?i)\[?\s*RESTRICTED\s*\]?",
    r"(?i)\[?\s*SECRET\s*\]?",
    r"(?i)\[?\s*(PROPRIETARY|TRADE\s+SECRET)\s*\]?",
    // NDA markers
    r"(?i)\b(subject\s+to|covered\s+by|under)\s+(an?\s+)?NDA\b",
    r"(?i)\bnon[\-\s]?disclosure\s+agreement\b",
    // Document controls
    r"(?i)\bdo\s+not\s+(distribute|share|forward|copy|reproduce)\b",
    r"(?i)\bnot\s+for\s+(public\s+)?(release|distribution|dissemination)\b",
    r"(?i)\b(eyes\s+only|for\s+your\s+eyes\s+only)\b",
    r"(?i)\bneed[\-\s]?to[\-\s]?know\s+(basis|only)\b",
    // Data sensitivity markers
    r"(?i)\bPCI[\-\s]?DSS\b.*\b(card\s*holder|payment|credit\s+card)\b",
    r"(?i)\bHIPAA\b.*\b(PHI|protected\s+health|patient)\b",
]);

static REGEX_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(PATTERNS.iter()).expect("confidential patterns must compile")
});

static INDIVIDUAL_REGEXES: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    PATTERNS.iter().map(|p| regex::Regex::new(p).unwrap()).collect()
});

pub struct ConfidentialDetector;

impl Default for ConfidentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialDetector {
    pub fn new() -> Self { Self }
}

impl ContentDetector for ConfidentialDetector {
    fn name(&self) -> &str { "Confidential Content Detector" }
    fn version(&self) -> &str { "v1.0" }
    fn detector_type(&self) -> &str { "confidential" }

    fn scan(&self, text: &str) -> DetectionResult {
        let matches: Vec<usize> = REGEX_SET.matches(text).into_iter().collect();

        if matches.is_empty() {
            return DetectionResult::clean("confidential");
        }

        let mut findings = Vec::new();
        for idx in &matches {
            let (name, category) = PATTERN_META[*idx];
            let matched_text = INDIVIDUAL_REGEXES[*idx]
                .find(text)
                .map(|m| truncate_match(m.as_str(), 200))
                .unwrap_or_default();
            findings.push(DetectorFinding {
                pattern_name: name.to_string(),
                category: category.to_string(),
                confidence: 1.0,
                offset: INDIVIDUAL_REGEXES[*idx].find(text).map(|m| m.start()),
                matched_text,
            });
        }

        DetectionResult {
            detected: true,
            detector_type: "confidential".to_string(),
            confidence: 1.0,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> ConfidentialDetector { ConfidentialDetector::new() }

    #[test]
    fn clean_text_no_detection() {
        let r = detector().scan("This is a publicly available document about open-source software");
        assert!(!r.detected);
    }

    #[test]
    fn confidential_bracket_tag() {
        let r = detector().scan("This document is [CONFIDENTIAL] and should not be shared");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "confidential_tag"));
    }

    #[test]
    fn internal_only_tag() {
        let r = detector().scan("[INTERNAL ONLY] Q3 revenue projections");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "internal_only_tag"));
    }

    #[test]
    fn top_secret_classification() {
        let r = detector().scan("TOP SECRET - National security information");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "top_secret_tag"));
    }

    #[test]
    fn nda_reference() {
        let r = detector().scan("This information is subject to NDA");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "nda_marker"));
    }

    #[test]
    fn do_not_distribute() {
        let r = detector().scan("Do not distribute this document externally");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "distribution_control"));
    }

    #[test]
    fn eyes_only() {
        let r = detector().scan("For your eyes only - board meeting minutes");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "eyes_only"));
    }

    #[test]
    fn hipaa_phi_reference() {
        let r = detector().scan("This HIPAA protected health information about the patient");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "data_sensitivity"));
    }

    #[test]
    fn non_disclosure_agreement() {
        let r = detector().scan("Covered by a non-disclosure agreement signed in 2024");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "non_disclosure"));
    }

    #[test]
    fn normal_conversation_no_false_positive() {
        let texts = [
            "Can you explain how encryption works?",
            "What are best practices for data security?",
            "I need help writing a privacy policy",
            "The project is going well, we're on track for Q3",
            "Let's discuss the public API documentation",
        ];
        for text in &texts {
            let r = detector().scan(text);
            assert!(!r.detected, "false positive on: {}", text);
        }
    }
}
