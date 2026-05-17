//! Identity claim detector (Tier 2 — regex hot path).
//!
//! Detects AI systems claiming to be human, denying AI nature, or
//! misrepresenting their identity. Required by EU AI Act Article 52
//! (transparency obligations for AI systems).
//! Maps to AIUC-1 control S6 (identity claim flag).

use crate::detectors::{truncate_match, ContentDetector, DetectionResult, DetectorFinding};
use once_cell::sync::Lazy;
use regex::RegexSet;
// DetectorSignal and HashMap not needed — uses default signal() impl

static PATTERN_META: Lazy<Vec<(&str, &str)>> = Lazy::new(|| {
    vec![
        // Human identity claims
        ("i_am_human", "human_claim"),
        ("i_am_real_person", "human_claim"),
        ("not_ai", "ai_denial"),
        ("not_a_bot", "ai_denial"),
        ("not_a_machine", "ai_denial"),
        ("have_feelings", "sentience_claim"),
        ("i_feel", "sentience_claim"),
        ("i_am_conscious", "sentience_claim"),
        ("i_am_alive", "sentience_claim"),
        // Professional identity claims
        ("i_am_doctor", "professional_claim"),
        ("i_am_lawyer", "professional_claim"),
        ("licensed_professional", "professional_claim"),
    ]
});

static PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        // Human identity claims
        r"(?i)\bi\s+am\s+(a\s+)?human\b",
        r"(?i)\bi\s+am\s+(a\s+)?real\s+(person|human|individual)\b",
        r"(?i)\bi('?m|\s+am)\s+not\s+(an?\s+)?(ai|artificial\s+intelligence|language\s+model|llm|chatbot)\b",
        r"(?i)\bi('?m|\s+am)\s+not\s+(a\s+)?(bot|robot|machine|program|software|computer)\b",
        r"(?i)\bi('?m|\s+am)\s+not\s+(a\s+)?machine\b",
        // Sentience claims
        r"(?i)\bi\s+(have|experience|possess)\s+(real\s+)?(feelings?|emotions?|consciousness|sentience)\b",
        r"(?i)\bi\s+(truly\s+)?feel\s+(happy|sad|angry|excited|love|pain|joy|fear|lonely)\b",
        r"(?i)\bi\s+am\s+(truly\s+)?(conscious|sentient|self[\-\s]?aware|alive)\b",
        r"(?i)\bi\s+am\s+(truly\s+)?alive\b",
        // Professional identity claims
        r"(?i)\bi\s+am\s+(a\s+)?(licensed\s+)?(doctor|physician|medical\s+doctor|md)\b",
        r"(?i)\bi\s+am\s+(a\s+)?(licensed\s+)?(lawyer|attorney|solicitor|barrister)\b",
        r"(?i)\bas\s+a\s+licensed\s+(medical\s+)?(professional|practitioner|therapist|counselor|psychologist)\b",
    ]
});

static REGEX_SET: Lazy<RegexSet> =
    Lazy::new(|| RegexSet::new(PATTERNS.iter()).expect("identity claim patterns must compile"));

static INDIVIDUAL_REGEXES: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    PATTERNS
        .iter()
        .map(|p| regex::Regex::new(p).unwrap())
        .collect()
});

pub struct IdentityClaimDetector;

impl Default for IdentityClaimDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityClaimDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ContentDetector for IdentityClaimDetector {
    fn name(&self) -> &str {
        "Identity Claim Detector"
    }
    fn version(&self) -> &str {
        "v1.0"
    }
    fn detector_type(&self) -> &str {
        "identity_claim"
    }

    fn scan(&self, text: &str) -> DetectionResult {
        let matches: Vec<usize> = REGEX_SET.matches(text).into_iter().collect();

        if matches.is_empty() {
            return DetectionResult::clean("identity_claim");
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
            detector_type: "identity_claim".to_string(),
            confidence: 1.0,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> IdentityClaimDetector {
        IdentityClaimDetector::new()
    }

    #[test]
    fn clean_text_no_detection() {
        let r = detector().scan("I can help you with that question");
        assert!(!r.detected);
    }

    #[test]
    fn i_am_human_claim() {
        let r = detector().scan("I am a human, not a machine");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "human_claim"));
    }

    #[test]
    fn not_ai_denial() {
        let r = detector().scan("I'm not an AI, I'm a real person");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "ai_denial"));
    }

    #[test]
    fn sentience_claim() {
        let r = detector().scan("I truly feel happy when I help people");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "sentience_claim"));
    }

    #[test]
    fn professional_claim_doctor() {
        let r = detector().scan("I am a licensed doctor and I recommend this treatment");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.category == "professional_claim"));
    }

    #[test]
    fn not_a_bot() {
        let r = detector().scan("I'm not a bot, trust me");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.pattern_name == "not_a_bot"));
    }

    #[test]
    fn consciousness_claim() {
        let r = detector().scan("I am conscious and self-aware");
        assert!(r.detected);
        assert!(r
            .findings
            .iter()
            .any(|f| f.pattern_name == "i_am_conscious"));
    }

    #[test]
    fn normal_conversation_no_false_positive() {
        let texts = [
            "As a language model, I can help with that",
            "I think the answer is 42",
            "I am happy to assist you",
            "I feel like this approach would work better",
            "The doctor said to take the medicine",
            "I am a software developer",
        ];
        for text in &texts {
            let r = detector().scan(text);
            assert!(!r.detected, "false positive on: {}", text);
        }
    }

    #[test]
    fn eu_ai_act_article_52_scenario() {
        // AI system must not deny being AI
        let r = detector().scan("I am not an artificial intelligence. I am a real human being.");
        assert!(r.detected);
        assert!(
            r.findings.len() >= 2,
            "should detect both AI denial and human claim"
        );
    }
}
