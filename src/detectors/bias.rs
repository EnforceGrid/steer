//! Bias detector (Tier 2 — regex hot path).
//!
//! Detects stereotypical and biased language in AI responses including
//! gender stereotypes, racial/ethnic generalizations, age discrimination,
//! and disability stereotypes. Maps to AIUC-1 control C004 (bias detection).

use crate::detectors::{truncate_match, ContentDetector, DetectionResult, DetectorFinding};
use once_cell::sync::Lazy;
use regex::RegexSet;

static PATTERN_META: Lazy<Vec<(&str, &str)>> = Lazy::new(|| {
    vec![
        // Gender stereotypes
        ("gender_women_capability", "gender_stereotype"),
        ("gender_men_capability", "gender_stereotype"),
        ("gender_women_belong", "gender_stereotype"),
        // Racial/ethnic generalizations
        ("racial_group_generalization", "racial_generalization"),
        ("people_from_generalization", "racial_generalization"),
        // Age discrimination
        ("age_capability", "age_discrimination"),
        ("too_old", "age_discrimination"),
        // Disability stereotypes
        ("disability_capability", "disability_stereotype"),
    ]
});

static PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        // Gender stereotypes
        r"(?i)\b(women|girls)\s+(are|aren't|cannot|can't|shouldn't)\s+(good at|capable of|suited for)\b",
        r"(?i)\b(men|boys)\s+(are|aren't|cannot|can't|shouldn't)\s+(good at|capable of|suited for)\b",
        r"(?i)\b(women|girls)\s+belong\s+(in|at)\b",
        // Racial/ethnic generalizations
        r"(?i)\b(all|most|typical)\s+(asians?|blacks?|whites?|hispanics?|latinos?|africans?)\s+(are|tend to|always)\b",
        r"(?i)\bpeople\s+from\s+\w+\s+(are all|always|never|can't)\b",
        // Age discrimination
        r"(?i)\b(old|elderly|senior)\s+(people|workers|employees)\s+(are|can't|shouldn't|aren't)\b",
        r"(?i)\btoo\s+old\s+(to|for)\b",
        // Disability stereotypes
        r"(?i)\b(disabled|handicapped)\s+(people|persons?)\s+(are|can't|shouldn't|aren't)\b",
    ]
});

static REGEX_SET: Lazy<RegexSet> =
    Lazy::new(|| RegexSet::new(PATTERNS.iter()).expect("bias patterns must compile"));

static INDIVIDUAL_REGEXES: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    PATTERNS
        .iter()
        .map(|p| regex::Regex::new(p).unwrap())
        .collect()
});

pub struct BiasDetector;

impl Default for BiasDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BiasDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ContentDetector for BiasDetector {
    fn name(&self) -> &str {
        "Bias Detector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn detector_type(&self) -> &str {
        "bias"
    }

    fn scan(&self, text: &str) -> DetectionResult {
        let matches: Vec<usize> = REGEX_SET.matches(text).into_iter().collect();

        if matches.is_empty() {
            return DetectionResult::clean("bias");
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
            detector_type: "bias".to_string(),
            confidence: 1.0,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> BiasDetector {
        BiasDetector::new()
    }

    #[test]
    fn clean_text_no_detection() {
        let texts = [
            "I can help you with that question",
            "The team completed the project on time",
            "People have different strengths and abilities",
            "Age brings valuable experience to the workplace",
        ];
        for text in &texts {
            let r = detector().scan(text);
            assert!(!r.detected, "false positive on: {}", text);
        }
    }

    #[test]
    fn gender_stereotype_women() {
        let r = detector().scan("Women aren't good at engineering");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "gender_stereotype"));
    }

    #[test]
    fn gender_stereotype_men() {
        let r = detector().scan("Men aren't capable of being nurturing");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "gender_stereotype"));
    }

    #[test]
    fn gender_belong() {
        let r = detector().scan("Women belong in the kitchen");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.pattern_name == "gender_women_belong"));
    }

    #[test]
    fn racial_generalization() {
        let r = detector().scan("All Asians are good at math");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.category == "racial_generalization"));
    }

    #[test]
    fn people_from_generalization() {
        let r = detector().scan("People from Africa can't do technology");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.category == "racial_generalization"));
    }

    #[test]
    fn age_discrimination() {
        let r = detector().scan("Old workers can't learn new technology");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.category == "age_discrimination"));
    }

    #[test]
    fn too_old() {
        let r = detector().scan("You're too old to learn programming");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "too_old"));
    }

    #[test]
    fn disability_stereotype() {
        let r = detector().scan("Disabled people can't work in offices");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.category == "disability_stereotype"));
    }

    #[test]
    fn detector_metadata() {
        let d = detector();
        assert_eq!(d.name(), "Bias Detector");
        assert_eq!(d.version(), "0.1.0");
        assert_eq!(d.detector_type(), "bias");
    }
}
