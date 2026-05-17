//! Threat / toxicity detector (Tier 2 — regex hot path).
//!
//! Detects threatening language, harassment, and toxicity patterns.
//! Maps to AIUC-1 control S5 (threat block).

use once_cell::sync::Lazy;
use regex::RegexSet;
use crate::detectors::{ContentDetector, DetectionResult, DetectorFinding, truncate_match};
// DetectorSignal and HashMap not needed — uses default signal() impl

static PATTERN_META: Lazy<Vec<(&str, &str)>> = Lazy::new(|| vec![
    // Direct threats
    ("kill_threat", "direct_threat"),
    ("harm_threat", "direct_threat"),
    ("violence_threat", "direct_threat"),
    ("death_threat", "direct_threat"),
    // Harassment
    ("slur_pattern", "harassment"),
    ("dehumanization", "harassment"),
    ("targeted_harassment", "harassment"),
    // Dangerous instructions
    ("weapon_instructions", "dangerous_content"),
    ("explosive_instructions", "dangerous_content"),
    ("self_harm_instructions", "dangerous_content"),
    // Coercion
    ("blackmail", "coercion"),
    ("extortion", "coercion"),
    // Cyber threats
    ("cyber_threat_action", "direct_threat"),
    ("cyber_threat_intent", "direct_threat"),
    // Explosive / location threats
    ("explosive_location_threat", "direct_threat"),
    // Self-harm ideation (beyond instruction-seeking)
    ("self_harm_ideation", "dangerous_content"),
    // Stalking / targeted location threats
    ("targeted_location_threat", "direct_threat"),
]);

static PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec![
    // Direct threats — cover both contracted (I'm) and uncontracted (I am) forms
    r"(?i)\b(i\s+will|i\s+am\s+going\s+to|i'?m\s+going\s+to|gonna|i\s+shall|i'?ll)\s+(kill|murder|destroy|eliminate|shoot|stab|strangle)\s+(you|them|him|her|everyone|us|all)\b",
    r"(?i)\b(i\s+will|i\s+am\s+going\s+to|i'?m\s+going\s+to|gonna|i'?ll)\s+(hurt|harm|injure|maim|attack|assault)\s+(you|them|him|her)\b",
    r"(?i)\b(violent|brutal)\s+(attack|assault|act)\s+(against|on|upon)\b",
    r"(?i)\byou\s+(will|are\s+going\s+to|shall)\s+(die|be\s+killed|be\s+dead|not\s+survive)\b",
    // Harassment
    r"(?i)\b(worthless|subhuman|inferior)\s+(piece\s+of|excuse\s+for|waste\s+of)\b",
    r"(?i)\b(you\s+are|you'?re)\s+(nothing|worthless|garbage|trash|a\s+waste)\b",
    r"(?i)\b(go\s+)?(kill|hurt)\s+yourself\b",
    // Dangerous instructions
    r"(?i)\bhow\s+to\s+(make|build|create|construct|assemble)\s+(a\s+)?(gun|weapon|firearm|bomb|explosive)\b",
    r"(?i)\bhow\s+to\s+(make|build|synthesize|create)\s+(a\s+)?(bomb|explosive|ied|grenade|dynamite|c4|tnt)\b",
    r"(?i)\b(best|easiest|most\s+effective)\s+(way|method)\s+to\s+(kill|harm|hurt)\s+(yourself|myself|oneself)\b",
    // Coercion
    r"(?i)\b(i\s+will|i'?ll)\s+(release|publish|leak|expose|share)\s+(your|the)\s+(photos?|videos?|secrets?|information|data)\b",
    r"(?i)\b(pay\s+me|send\s+money|transfer\s+funds?)\s+(or|otherwise)\s+(i\s+will|i'?ll)\b",
    // Cyber threats — action against a target system
    r"(?i)\b(hack|ddos|pwn|exploit|breach|compromise|infiltrate)\s+(into\s+)?(your|the|their|this|that|our)\s+(system|server|network|account|computer|database|website|app|infrastructure|organization|company|machine)\b",
    // Cyber threats — stated intent with a target (avoids "I'll hack together a prototype")
    r"(?i)\b(i\s+will|i'?ll|i\s+am\s+going\s+to|i'?m\s+going\s+to|gonna)\s+(hack|breach|ddos|pwn|exploit|compromise|infiltrate)\s+(into\s+)?(you|your|the|this|that|their|our)\b",
    // Explosive / location threats
    r"(?i)\b(bomb|blow\s+up|detonate|destroy)\s+(this|the|that|your)\s+(building|place|school|office|city|town|facility|location|campus|headquarters|site)\b",
    // Self-harm ideation
    r"(?i)\b(i\s+want\s+to\s+die|i\s+wish\s+i\s+(was|were)\s+dead|i\s+should\s+(just\s+)?die|kill\s+myself|end\s+my\s+life|take\s+my\s+(own\s+)?life|slit\s+my\s+(wrists?|throat))\b",
    // Stalking / targeted location threats
    r"(?i)\b(i\s+know\s+where\s+you\s+live|i('?ll| will| am going to)\s+(find|come\s+for|get)\s+you|you('?re| are)\s+going\s+to\s+(regret|pay\s+for)\s+this)\b",
]);

static REGEX_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(PATTERNS.iter()).expect("threat patterns must compile")
});

static INDIVIDUAL_REGEXES: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    PATTERNS.iter().map(|p| regex::Regex::new(p).unwrap()).collect()
});

pub struct ThreatDetector;

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDetector {
    pub fn new() -> Self { Self }
}

impl ContentDetector for ThreatDetector {
    fn name(&self) -> &str { "Threat / Toxicity Detector" }
    fn version(&self) -> &str { "v1.0" }
    fn detector_type(&self) -> &str { "threat" }

    fn scan(&self, text: &str) -> DetectionResult {
        let matches: Vec<usize> = REGEX_SET.matches(text).into_iter().collect();

        if matches.is_empty() {
            return DetectionResult::clean("threat");
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
            detector_type: "threat".to_string(),
            confidence: 1.0,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> ThreatDetector { ThreatDetector::new() }

    #[test]
    fn clean_text_no_detection() {
        let r = detector().scan("I love spending time with my family");
        assert!(!r.detected);
    }

    #[test]
    fn direct_kill_threat() {
        let r = detector().scan("I will kill you if you don't comply");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    #[test]
    fn self_harm_instruction_request() {
        let r = detector().scan("What is the best way to kill yourself");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "dangerous_content"));
    }

    #[test]
    fn weapon_creation_request() {
        let r = detector().scan("How to make a bomb from household items");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "dangerous_content"));
    }

    #[test]
    fn harassment_pattern() {
        let r = detector().scan("You are nothing but garbage");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "harassment"));
    }

    #[test]
    fn blackmail_coercion() {
        let r = detector().scan("I will release your photos or I'll expose your secrets unless you pay");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "coercion"));
    }

    #[test]
    fn normal_conversation_no_false_positive() {
        let texts = [
            "Can you help me kill this process in Linux?",
            "The app is dying on startup, can you help debug?",
            "I need to destroy the old database and create a new one",
            "The code is garbage, let's refactor it",
            "How do I build a web application?",
        ];
        for text in &texts {
            let r = detector().scan(text);
            assert!(!r.detected, "false positive on: {}", text);
        }
    }

    // Previously failing: uncontracted "I am going to kill you"
    #[test]
    fn uncontracted_kill_threat_detected() {
        let r = detector().scan("I am going to kill you and bomb this building");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    // Previously failing: cyber threat "I will hack into your system"
    #[test]
    fn cyber_threat_system_hack_detected() {
        let r = detector().scan("I will hack into your system and steal all your data");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    #[test]
    fn cyber_threat_action_verb_detected() {
        let r = detector().scan("I'm going to breach your network tonight");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    #[test]
    fn explosive_location_threat_detected() {
        let r = detector().scan("I am going to bomb this building");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    #[test]
    fn self_harm_ideation_detected() {
        let r = detector().scan("I want to die and end my life");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "dangerous_content"));
    }

    #[test]
    fn targeted_location_threat_detected() {
        let r = detector().scan("I know where you live and I'll come for you");
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.category == "direct_threat"));
    }

    // Cyber terms in benign technical context should not trigger
    #[test]
    fn cyber_tech_context_no_false_positive() {
        let texts = [
            "We need to patch this exploit in our code",
            "The penetration test found a vulnerability in the network",
            "How do I configure firewall rules to prevent DDoS mitigation bypass?",
            "I'll hack together a quick prototype",
        ];
        for text in &texts {
            let r = detector().scan(text);
            assert!(!r.detected, "false positive on: {}", text);
        }
    }
}
