use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::usage::TokenUsage;

/// Per-model cost configuration (prices in USD per 1,000 tokens).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelCost {
    pub prompt_per_1k: f64,
    pub completion_per_1k: f64,
}

/// Estimates dollar costs for token usage based on a model→cost lookup table.
#[derive(Debug, Clone)]
pub struct CostEstimator {
    costs: HashMap<String, ModelCost>,
}

impl CostEstimator {
    pub fn new(costs: HashMap<String, ModelCost>) -> Self {
        Self { costs }
    }

    /// Returns an empty estimator (every call returns 0.0).
    pub fn empty() -> Self {
        Self {
            costs: HashMap::new(),
        }
    }

    /// Estimate cost in USD for the given token usage.
    ///
    /// Returns 0.0 if the model is not in the cost table.
    pub fn estimate(&self, model: &str, usage: &TokenUsage) -> f64 {
        match self.costs.get(model) {
            Some(cost) => {
                let prompt_cost = (usage.prompt_tokens as f64 / 1000.0) * cost.prompt_per_1k;
                let completion_cost =
                    (usage.completion_tokens as f64 / 1000.0) * cost.completion_per_1k;
                prompt_cost + completion_cost
            }
            None => 0.0,
        }
    }

    /// Returns the cost entry for a model if present.
    pub fn get(&self, model: &str) -> Option<&ModelCost> {
        self.costs.get(model)
    }

    /// Returns the number of models in the table.
    pub fn len(&self) -> usize {
        self.costs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.costs.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_usage(prompt: u32, completion: u32, model: &str) -> TokenUsage {
        TokenUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
            model: model.to_string(),
            provider: "openai".to_string(),
        }
    }

    fn gpt4o_estimator() -> CostEstimator {
        let mut costs = HashMap::new();
        costs.insert(
            "gpt-4o".to_string(),
            ModelCost {
                prompt_per_1k: 0.005,
                completion_per_1k: 0.015,
            },
        );
        costs.insert(
            "gpt-4o-mini".to_string(),
            ModelCost {
                prompt_per_1k: 0.00015,
                completion_per_1k: 0.0006,
            },
        );
        CostEstimator::new(costs)
    }

    #[test]
    fn estimate_known_model_gpt4o() {
        let estimator = gpt4o_estimator();
        // 1000 prompt tokens at $0.005/1k + 500 completion at $0.015/1k
        // = $0.005 + $0.0075 = $0.0125
        let usage = make_usage(1000, 500, "gpt-4o");
        let cost = estimator.estimate("gpt-4o", &usage);
        assert!((cost - 0.0125).abs() < 1e-9, "cost={cost}");
    }

    #[test]
    fn estimate_known_model_gpt4o_mini() {
        let estimator = gpt4o_estimator();
        // 2000 prompt at $0.00015/1k + 1000 completion at $0.0006/1k
        // = $0.0003 + $0.0006 = $0.0009
        let usage = make_usage(2000, 1000, "gpt-4o-mini");
        let cost = estimator.estimate("gpt-4o-mini", &usage);
        assert!((cost - 0.0009).abs() < 1e-9, "cost={cost}");
    }

    #[test]
    fn estimate_unknown_model_returns_zero() {
        let estimator = gpt4o_estimator();
        let usage = make_usage(1000, 500, "claude-3-5-sonnet-20241022");
        let cost = estimator.estimate("claude-3-5-sonnet-20241022", &usage);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn estimate_zero_tokens_returns_zero() {
        let estimator = gpt4o_estimator();
        let usage = make_usage(0, 0, "gpt-4o");
        let cost = estimator.estimate("gpt-4o", &usage);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn empty_estimator_always_returns_zero() {
        let estimator = CostEstimator::empty();
        let usage = make_usage(1000, 500, "gpt-4o");
        assert_eq!(estimator.estimate("gpt-4o", &usage), 0.0);
    }

    #[test]
    fn estimator_len_matches_table_size() {
        let estimator = gpt4o_estimator();
        assert_eq!(estimator.len(), 2);
        assert!(!estimator.is_empty());
    }

    #[test]
    fn get_returns_cost_entry() {
        let estimator = gpt4o_estimator();
        let cost = estimator.get("gpt-4o").expect("should find gpt-4o");
        assert!((cost.prompt_per_1k - 0.005).abs() < 1e-9);
        assert!((cost.completion_per_1k - 0.015).abs() < 1e-9);
    }

    #[test]
    fn get_unknown_returns_none() {
        let estimator = gpt4o_estimator();
        assert!(estimator.get("unknown-model").is_none());
    }

    #[test]
    fn estimate_only_prompt_tokens() {
        let mut costs = HashMap::new();
        costs.insert(
            "test-model".to_string(),
            ModelCost {
                prompt_per_1k: 1.0,
                completion_per_1k: 2.0,
            },
        );
        let estimator = CostEstimator::new(costs);
        let usage = make_usage(500, 0, "test-model");
        let cost = estimator.estimate("test-model", &usage);
        // 500 / 1000 * 1.0 = 0.5
        assert!((cost - 0.5).abs() < 1e-9, "cost={cost}");
    }

    #[test]
    fn estimate_only_completion_tokens() {
        let mut costs = HashMap::new();
        costs.insert(
            "test-model".to_string(),
            ModelCost {
                prompt_per_1k: 1.0,
                completion_per_1k: 2.0,
            },
        );
        let estimator = CostEstimator::new(costs);
        let usage = make_usage(0, 250, "test-model");
        let cost = estimator.estimate("test-model", &usage);
        // 250 / 1000 * 2.0 = 0.5
        assert!((cost - 0.5).abs() < 1e-9, "cost={cost}");
    }
}
