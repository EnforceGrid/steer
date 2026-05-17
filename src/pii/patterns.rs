use once_cell::sync::Lazy;
use regex::Regex;

pub struct PiiPattern {
    pub name: &'static str,
    pub regex: Lazy<Regex>,
    pub redact_to: &'static str,
}

macro_rules! pii_pattern {
    ($name:expr, $pattern:expr, $redact:expr) => {
        PiiPattern {
            name: $name,
            regex: Lazy::new(|| Regex::new($pattern).expect("invalid PII regex")),
            redact_to: $redact,
        }
    };
}

// ── Personal data ────────────────────────────────────────────────────────────

pub static CREDIT_CARD: PiiPattern = pii_pattern!(
    "credit_card",
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b",
    "[REDACTED_CREDIT_CARD]"
);

pub static SSN: PiiPattern =
    pii_pattern!("ssn", r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "[REDACTED_SSN]");

pub static EMAIL: PiiPattern = pii_pattern!(
    "email",
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "[REDACTED_EMAIL]"
);

pub static PHONE: PiiPattern = pii_pattern!(
    "phone",
    // US format — two branches: parens (no leading \b since ( isn't \w) and digits-with-separator
    r"(?:\+1[-.\s]?)?\([0-9]{3}\)[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b|\b(?:\+1[-.\s]?)?[0-9]{3}[-.\s][0-9]{3}[-.\s]?[0-9]{4}\b",
    "[REDACTED_PHONE]"
);

pub static PHONE_INTL: PiiPattern = pii_pattern!(
    "phone_intl",
    // International: +<country code> followed by 7-12 digits with optional separators
    r"\+[1-9][0-9]{0,2}[\s.-]?(?:[0-9][\s.-]?){7,12}\b",
    "[REDACTED_PHONE]"
);

pub static IP_ADDRESS: PiiPattern = pii_pattern!(
    "ip_address",
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "[REDACTED_IP]"
);

// ── Auth tokens & secrets ────────────────────────────────────────────────────

pub static OPENAI_KEY: PiiPattern = pii_pattern!(
    "openai_key",
    r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "[REDACTED_API_KEY]"
);

pub static ANTHROPIC_KEY: PiiPattern = pii_pattern!(
    "anthropic_key",
    r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
    "[REDACTED_API_KEY]"
);

pub static AWS_ACCESS_KEY: PiiPattern = pii_pattern!(
    "aws_access_key",
    r"\bAKIA[0-9A-Z]{16}\b",
    "[REDACTED_AWS_KEY]"
);

pub static AWS_SECRET_KEY: PiiPattern = pii_pattern!(
    "aws_secret_key",
    r"(?i)(?:aws_secret_access_key|secret_?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    "[REDACTED_AWS_SECRET]"
);

pub static GITHUB_TOKEN: PiiPattern = pii_pattern!(
    "github_token",
    // ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server), ghr_ (refresh)
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
    "[REDACTED_GITHUB_TOKEN]"
);

pub static SLACK_TOKEN: PiiPattern = pii_pattern!(
    "slack_token",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "[REDACTED_SLACK_TOKEN]"
);

pub static STRIPE_KEY: PiiPattern = pii_pattern!(
    "stripe_key",
    r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b",
    "[REDACTED_STRIPE_KEY]"
);

pub static JWT: PiiPattern = pii_pattern!(
    "jwt",
    // Three base64url segments: header.payload.signature
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "[REDACTED_JWT]"
);

pub static BEARER_TOKEN: PiiPattern = pii_pattern!(
    "bearer_token",
    // Bearer tokens embedded in message content (not HTTP headers)
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "[REDACTED_BEARER]"
);

pub static GENERIC_SECRET: PiiPattern = pii_pattern!(
    "generic_secret",
    // key=, secret=, token=, password=, api_key= followed by a long value
    r#"(?i)(?:api_?key|secret|token|password|passwd|credentials?)\s*[=:]\s*['"]?[A-Za-z0-9._~+/=-]{16,}['"]?"#,
    "[REDACTED_SECRET]"
);

// ── Financial identifiers ────────────────────────────────────────────────────

pub static IBAN: PiiPattern = pii_pattern!(
    "iban",
    r"\b[A-Z]{2}[0-9]{2}[A-Za-z0-9]{4}[0-9]{7}(?:[A-Za-z0-9]{0,16})\b",
    "[REDACTED_IBAN]"
);

// ── Cloud provider keys ──────────────────────────────────────────────────────

pub static AZURE_KEY: PiiPattern = pii_pattern!(
    "azure_key",
    // Azure Storage account key: 86 base64 chars + "==" padding.
    // No trailing \b because "=" is not a word char and \b would never fire.
    r"\b[A-Za-z0-9+/]{86}==",
    "[REDACTED_AZURE_KEY]"
);

pub static GOOGLE_API_KEY: PiiPattern = pii_pattern!(
    "google_api_key",
    r"\bAIza[A-Za-z0-9_\-]{35}\b",
    "[REDACTED_GOOGLE_KEY]"
);

// ── Registry ─────────────────────────────────────────────────────────────────

pub fn all_patterns() -> Vec<&'static PiiPattern> {
    vec![
        // Personal data
        &CREDIT_CARD,
        &SSN,
        &EMAIL,
        &PHONE,
        &PHONE_INTL,
        &IP_ADDRESS,
        // Financial
        &IBAN,
        // Auth tokens — specific patterns before generic to get accurate labels
        &ANTHROPIC_KEY,
        &OPENAI_KEY,
        &AWS_ACCESS_KEY,
        &AWS_SECRET_KEY,
        &GITHUB_TOKEN,
        &SLACK_TOKEN,
        &STRIPE_KEY,
        &JWT,
        &BEARER_TOKEN,
        &GENERIC_SECRET,
        // Cloud provider keys
        &AZURE_KEY,
        &GOOGLE_API_KEY,
    ]
}

pub fn pattern_by_name(name: &str) -> Option<&'static PiiPattern> {
    all_patterns().into_iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &PiiPattern, text: &str) -> bool {
        pattern.regex.is_match(text)
    }

    // ── Phone patterns ───────────────────────────────────────────────────

    #[test]
    fn phone_us_with_dashes() {
        assert!(matches(&PHONE, "call 555-867-5309 now"));
    }

    #[test]
    fn phone_us_with_parens() {
        assert!(matches(&PHONE, "call (555) 867-5309 now"));
    }

    #[test]
    fn phone_us_no_separator_does_not_match() {
        // Avoids false positives on timestamps / IDs
        assert!(!matches(&PHONE, "id 5558675309 here"));
    }

    #[test]
    fn phone_intl_india_no_spaces() {
        assert!(matches(&PHONE_INTL, "phone +919012321312 ok"));
    }

    #[test]
    fn phone_intl_india_with_spaces() {
        assert!(matches(&PHONE_INTL, "phone +91 90123 21312 ok"));
    }

    #[test]
    fn phone_intl_uk() {
        assert!(matches(&PHONE_INTL, "call +44 7700 900000 now"));
    }

    #[test]
    fn phone_intl_us_plus1() {
        assert!(matches(&PHONE_INTL, "call +1-555-867-5309 now"));
    }

    // ── Auth token patterns ──────────────────────────────────────────────

    #[test]
    fn openai_key_matches() {
        assert!(matches(&OPENAI_KEY, "key: sk-abc123def456ghi789jkl012mno"));
    }

    #[test]
    fn anthropic_key_matches() {
        assert!(matches(&ANTHROPIC_KEY, "key: sk-ant-abc123def456ghi789jkl"));
    }

    #[test]
    fn aws_access_key_matches() {
        assert!(matches(&AWS_ACCESS_KEY, "key AKIAIOSFODNN7EXAMPLE here"));
    }

    #[test]
    fn github_token_matches() {
        assert!(matches(
            &GITHUB_TOKEN,
            "token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234"
        ));
    }

    #[test]
    fn jwt_matches() {
        assert!(matches(&JWT, "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
    }

    #[test]
    fn bearer_token_matches() {
        assert!(matches(
            &BEARER_TOKEN,
            "use Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxx"
        ));
    }

    #[test]
    fn generic_secret_matches() {
        assert!(matches(
            &GENERIC_SECRET,
            r#"api_key="sk_test_abcdef1234567890""#
        ));
        assert!(matches(&GENERIC_SECRET, "password=SuperSecretPass1234!"));
    }

    #[test]
    fn slack_token_matches() {
        assert!(matches(&SLACK_TOKEN, "xoxb-1234567890-abcdefghij"));
    }

    #[test]
    fn stripe_key_matches() {
        assert!(matches(&STRIPE_KEY, "sk_live_abcdefghijklmnopqrst1234"));
    }

    // ── False positive guards ────────────────────────────────────────────

    #[test]
    fn unix_timestamp_not_matched_as_phone() {
        assert!(!matches(&PHONE, "\"created\": 1714089931"));
        assert!(!matches(&PHONE_INTL, "\"created\": 1714089931"));
    }

    #[test]
    fn short_token_not_matched_as_secret() {
        assert!(!matches(&GENERIC_SECRET, "token=abc")); // too short
    }

    // ── IBAN ─────────────────────────────────────────────────────────────

    #[test]
    fn iban_gb_matches() {
        assert!(matches(&IBAN, "IBAN: GB29NWBK60161331926819 please"));
    }

    #[test]
    fn iban_de_matches() {
        assert!(matches(&IBAN, "send to DE89370400440532013000 today"));
    }

    #[test]
    fn iban_short_no_match() {
        // Too short to be a valid IBAN structure
        assert!(!matches(&IBAN, "code AB12XY"));
    }

    // ── Azure key ────────────────────────────────────────────────────────

    #[test]
    fn azure_key_matches() {
        // Exactly 86 base64 chars (A-Za-z0-9+/) + == padding = 88 chars total.
        // 64 base64 alphabet chars + 22 uppercase = ABCDEFGHIJKLMNOPQRSTUV = 86.
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUV==";
        // Verify length at compile time via the assertion.
        assert_eq!(
            key.len(),
            88,
            "key string must be 88 chars (86 base64 + ==)"
        );
        assert!(matches(&AZURE_KEY, &format!("key {key}")));
    }

    #[test]
    fn azure_key_wrong_length_no_match() {
        // 85 base64 chars + == = 87 chars total — one short, must not match.
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTU==";
        assert_eq!(key.len(), 87, "must be 87 chars (85 base64 + ==)");
        assert!(!matches(&AZURE_KEY, &format!("key {key}")));
    }

    // ── Google API key ───────────────────────────────────────────────────

    #[test]
    fn google_api_key_matches() {
        // AIza prefix + exactly 35 alphanumeric/_/- chars = 39 chars total.
        let key = "AIzaSyD-9tSrke72Jiz2siaB_XABCDEFGHIJKlm";
        assert_eq!(key.len(), 39, "AIza (4) + 35 = 39");
        assert!(matches(&GOOGLE_API_KEY, &format!("key {key} ok")));
    }

    #[test]
    fn google_api_key_wrong_prefix_no_match() {
        assert!(!matches(
            &GOOGLE_API_KEY,
            "key BIzaSyD-9tSrke72Jiz2siaB_XABCDEFGHIJKlm ok"
        ));
    }
}
