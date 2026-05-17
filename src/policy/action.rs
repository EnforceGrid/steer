use serde::{Deserialize, Serialize};

/// Five-valued enforcement action — mirrors cadabra.core.EnforcementAction.
/// Precedence: Allow < Transform < Flag < Steer < Block (most restrictive wins).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementAction {
    Allow,
    Transform,
    Flag,
    Steer,
    Block,
}

impl EnforcementAction {
    /// Resolve a set of actions to the single most-restrictive outcome.
    pub fn resolve<I: IntoIterator<Item = EnforcementAction>>(actions: I) -> EnforcementAction {
        actions
            .into_iter()
            .max()
            .unwrap_or(EnforcementAction::Allow)
    }

    /// Whether this action requires modifying the request/response body.
    /// Allow and Flag are observation-only — the body passes through unmodified.
    /// Transform, Steer, and Block require body modifications (redaction, injection, etc.).
    pub fn requires_body_modification(&self) -> bool {
        matches!(self, Self::Transform | Self::Steer | Self::Block)
    }
}

impl std::fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Transform => write!(f, "transform"),
            Self::Flag => write!(f, "flag"),
            Self::Steer => write!(f, "steer"),
            Self::Block => write!(f, "block"),
        }
    }
}
