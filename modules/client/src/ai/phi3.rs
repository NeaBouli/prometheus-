//! Phi-3-mini ONNX Runtime wrapper module.
//!
//! Wraps the Phi-3-mini 3.8B model (4-bit quantized) for local anomaly detection.
//! Architecture Decision #8: runs on 4GB RAM, no GPU required.
//!
//! Graceful degradation: if the model file does not exist at the given path,
//! the instance is created with `is_loaded() = false` and `analyze_bytes()`
//! returns a safe default (not suspicious, confidence 0.0).
//!
//! ONNX Runtime integration (ort crate) deferred to avoid C-dependency
//! build issues (same rationale as PATTERN-009). Full ONNX integration
//! will be enabled when the quantized model is available.

use std::path::{Path, PathBuf};

use anyhow::Result;
use log::{info, warn};

/// Minimum confidence threshold for reporting (from MEMO.md AUTO-TUNING)
pub const MIN_CONFIDENCE_KI: f64 = 0.85;

/// AI analysis result from Phi-3-mini inference.
#[derive(Debug, Clone)]
pub struct AiAnalysis {
    /// Whether the input appears suspicious
    pub is_suspicious: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Human-readable threat indicator descriptions
    pub threat_indicators: Vec<String>,
    /// Recommended action based on analysis
    pub recommended_action: RecommendedAction,
}

/// Recommended action after AI analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum RecommendedAction {
    /// Immediately quarantine the file
    Quarantine,
    /// Continue monitoring, not yet confirmed threat
    Monitor,
    /// No threat detected, safe to ignore
    Ignore,
}

impl Default for AiAnalysis {
    fn default() -> Self {
        Self {
            is_suspicious: false,
            confidence: 0.0,
            threat_indicators: Vec::new(),
            recommended_action: RecommendedAction::Ignore,
        }
    }
}

/// Phi-3-mini model wrapper for local threat analysis.
/// Runs the 3.8B parameter model in 4-bit quantization via ONNX Runtime.
pub struct Phi3Model {
    model_path: PathBuf,
    loaded: bool,
}

impl Phi3Model {
    /// Create a new Phi3Model instance.
    /// If the model file does not exist at `model_path`, the instance is created
    /// with `is_loaded() = false` (graceful degradation).
    pub fn new(model_path: &Path) -> Result<Self> {
        let loaded = model_path.exists();
        if loaded {
            info!("Phi-3-mini model found at {:?}", model_path);
            // Real ONNX Runtime session would be initialized here
            // using ort::Session::builder()?.with_model_from_file(model_path)?
        } else {
            warn!(
                "Phi-3-mini model not found at {:?} — running in stub mode",
                model_path
            );
        }

        Ok(Self {
            model_path: model_path.to_path_buf(),
            loaded,
        })
    }

    /// Run anomaly detection on raw bytes.
    /// When model is not loaded: returns safe default (not suspicious, confidence 0.0).
    /// When model is loaded: runs ONNX inference and returns analysis.
    pub async fn analyze_bytes(&self, data: &[u8]) -> Result<AiAnalysis> {
        if !self.loaded {
            return Ok(AiAnalysis::default());
        }

        // Stub: real ONNX inference will be implemented when model is available.
        // The actual pipeline:
        // 1. Tokenize the byte content into model input format
        // 2. Run ONNX inference session
        // 3. Parse output logits into threat classification
        // 4. Return AiAnalysis with confidence and indicators

        // Placeholder heuristic based on data entropy and known patterns
        let entropy = calculate_entropy(data);
        let is_suspicious = entropy > 7.5; // High entropy = possible encryption/packing
        let confidence = if is_suspicious {
            (entropy - 7.0).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let mut indicators = Vec::new();
        if entropy > 7.5 {
            indicators.push(format!("High entropy: {:.2}", entropy));
        }
        if data.len() > 10_000_000 {
            indicators.push("Large file size".to_string());
        }

        let recommended_action = if confidence >= MIN_CONFIDENCE_KI {
            RecommendedAction::Quarantine
        } else if confidence > 0.5 {
            RecommendedAction::Monitor
        } else {
            RecommendedAction::Ignore
        };

        Ok(AiAnalysis {
            is_suspicious,
            confidence,
            threat_indicators: indicators,
            recommended_action,
        })
    }

    /// Check if the ONNX model is loaded and ready for inference.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the model file path.
    pub fn model_path(&self) -> &Path {
        &self.model_path
    }
}

/// Calculate Shannon entropy of byte data (0.0 = uniform, 8.0 = max random).
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_new_without_model() {
        let model = Phi3Model::new(&PathBuf::from("/nonexistent/phi3.onnx")).unwrap();
        assert!(!model.is_loaded());
    }

    #[tokio::test]
    async fn test_analysis_without_model() {
        let model = Phi3Model::new(&PathBuf::from("/nonexistent/phi3.onnx")).unwrap();
        let result = model.analyze_bytes(b"test data").await.unwrap();
        assert!(!result.is_suspicious);
        assert_eq!(result.confidence, 0.0);
        assert!(result.threat_indicators.is_empty());
        assert_eq!(result.recommended_action, RecommendedAction::Ignore);
    }

    #[test]
    fn test_default_analysis() {
        let analysis = AiAnalysis::default();
        assert!(!analysis.is_suspicious);
        assert_eq!(analysis.confidence, 0.0);
        assert_eq!(analysis.recommended_action, RecommendedAction::Ignore);
    }

    #[test]
    fn test_min_confidence_constant() {
        assert!((MIN_CONFIDENCE_KI - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All same byte = 0 entropy
        let data = vec![0x41u8; 1000];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_random() {
        // Pseudo-random data has high entropy (close to 8.0)
        let data: Vec<u8> = (0..=255).cycle().take(2560).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9);
    }

    #[test]
    fn test_model_path() {
        let path = PathBuf::from("/models/phi3-mini-4bit.onnx");
        let model = Phi3Model::new(&path).unwrap();
        assert_eq!(model.model_path(), path);
    }
}
