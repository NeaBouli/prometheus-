//! Phi-3-mini ONNX Runtime wrapper module.
//!
//! Wraps the Phi-3-mini 3.8B model (4-bit quantized) for local anomaly detection.
//! Architecture Decision #8: runs on 4GB RAM, no GPU required.
//!
//! Fail-closed stub: no ONNX runtime is integrated yet, so `is_loaded()` is
//! always `false` — even when a file exists at the configured path — and
//! `analyze_bytes()` always returns a safe default (not suspicious,
//! confidence 0.0, no quarantine authority). The mere presence of a file
//! must never be reported as a loaded model, and a heuristic must never
//! emit suspicious/malware/quarantine decisions.
//!
//! ONNX Runtime integration (ort crate) deferred to avoid C-dependency
//! build issues (same rationale as PATTERN-009). Full ONNX integration
//! will be enabled when the quantized model is available.

use std::path::{Path, PathBuf};

use anyhow::Result;
use log::warn;

use crate::runtime::{require_stub_allowed_for, RuntimeMode};

/// Minimum confidence threshold for reporting (from MEMO.md AUTO-TUNING)
pub const MIN_CONFIDENCE_KI: f64 = 0.85;

/// Maximum caller-supplied analysis input accepted by the development stub.
pub const MAX_ANALYSIS_BYTES: usize = 16 * 1024 * 1024;

/// Result shape reserved for future Phi-3-mini inference.
///
/// The current stub returns only [`AiAnalysis::default`]. None of these fields
/// grants malware-verdict, quarantine, reporting, or other action authority.
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
    /// Legacy advisory label reserved for future reviewed inference.
    ///
    /// This label is not quarantine authority and is never emitted by the
    /// current development stub.
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
}

impl Phi3Model {
    /// Create a new Phi3Model instance.
    ///
    /// Fail-closed: until a real ONNX Runtime session is wired in, the stub
    /// never reports a loaded model, even if a file exists at `model_path`.
    /// A path existing on disk is not proof of a validated model.
    pub fn new(model_path: &Path) -> Result<Self> {
        warn!("Phi-3-mini ONNX runtime is unavailable; running in fail-closed stub mode");

        Ok(Self {
            model_path: model_path.to_path_buf(),
        })
    }

    /// Run anomaly detection on raw bytes.
    ///
    /// Fail-closed stub: gated by the runtime profile (rejected in beta and
    /// mainnet), and otherwise always returns a safe default — never
    /// suspicious and never quarantine. Inputs above 16 MiB fail closed.
    pub async fn analyze_bytes(&self, data: &[u8]) -> Result<AiAnalysis> {
        stub_analysis(RuntimeMode::from_env(), data.len())
    }

    /// Check if the ONNX model is loaded and ready for inference.
    /// Always `false` while the runtime is a stub without ONNX integration.
    pub fn is_loaded(&self) -> bool {
        false
    }

    /// Get the model file path.
    pub fn model_path(&self) -> &Path {
        &self.model_path
    }
}

/// Fail-closed stub analysis for an explicit runtime mode.
///
/// Security-critical placeholder behavior is rejected in beta/mainnet; in
/// development the stub returns a safe default and never emits suspicion,
/// confidence, or quarantine authority from heuristics.
fn stub_analysis(mode: RuntimeMode, input_len: usize) -> Result<AiAnalysis> {
    require_stub_allowed_for(mode, "Phi-3 model stub")?;
    if input_len > MAX_ANALYSIS_BYTES {
        anyhow::bail!("Phi-3 analysis input exceeds the 16 MiB limit");
    }
    Ok(AiAnalysis::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Maximal-entropy input: every byte value equally often (entropy = 8.0).
    fn high_entropy_bytes() -> Vec<u8> {
        (0..=255u8).cycle().take(2560).collect()
    }

    /// Create a fake "model" file on disk (bytes are not a real ONNX model).
    fn fake_model_file() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"\x08\x03fake-phi3-mini-4bit-not-a-real-onnx-model")
            .unwrap();
        file
    }

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
    fn test_model_path() {
        let path = PathBuf::from("/models/phi3-mini-4bit.onnx");
        let model = Phi3Model::new(&path).unwrap();
        assert_eq!(model.model_path(), path);
    }

    /// Adversarial: an existing file at the model path must NOT be reported
    /// as a loaded ONNX model — path existence is not proof of a model.
    #[test]
    fn test_existing_fake_model_file_is_not_loaded() {
        let file = fake_model_file();
        let model = Phi3Model::new(file.path()).unwrap();
        assert!(!model.is_loaded());
    }

    /// Adversarial: even with a file present at the model path and
    /// maximal-entropy input, the stub must stay fail-closed — no suspicion,
    /// no confidence, no indicators, no quarantine authority.
    #[tokio::test]
    async fn test_high_entropy_input_stays_fail_closed_with_fake_model() {
        let file = fake_model_file();
        let model = Phi3Model::new(file.path()).unwrap();
        let result = model.analyze_bytes(&high_entropy_bytes()).await.unwrap();
        assert!(!result.is_suspicious);
        assert_eq!(result.confidence, 0.0);
        assert!(result.threat_indicators.is_empty());
        assert_eq!(result.recommended_action, RecommendedAction::Ignore);
    }

    /// The stub must never recommend quarantine, whatever the input.
    #[tokio::test]
    async fn test_stub_never_recommends_quarantine() {
        let model = Phi3Model::new(&PathBuf::from("/nonexistent/phi3.onnx")).unwrap();
        for data in [&b""[..], &high_entropy_bytes(), &vec![0x41u8; 1000]] {
            let result = model.analyze_bytes(data).await.unwrap();
            assert_eq!(result.recommended_action, RecommendedAction::Ignore);
            assert!(result.confidence < MIN_CONFIDENCE_KI);
        }
    }

    /// Input bounds: empty and exactly-maximal inputs return the safe default,
    /// while an oversized input fails closed without analysis.
    #[tokio::test]
    async fn test_input_bounds_fail_closed() {
        let model = Phi3Model::new(&PathBuf::from("/nonexistent/phi3.onnx")).unwrap();
        for data in [&b""[..], &vec![0u8; MAX_ANALYSIS_BYTES]] {
            let result = model.analyze_bytes(data).await.unwrap();
            assert_eq!(result.recommended_action, RecommendedAction::Ignore);
            assert!(!result.is_suspicious);
        }

        let oversized = vec![0u8; MAX_ANALYSIS_BYTES + 1];
        assert!(model.analyze_bytes(&oversized).await.is_err());
    }

    /// Production profiles reject the security-critical stub outright.
    /// Tested through the explicit-mode helper to stay deterministic without
    /// mutating process env in parallel tests.
    #[test]
    fn test_production_profiles_reject_stub() {
        assert!(stub_analysis(RuntimeMode::Development, 0).is_ok());
        assert!(stub_analysis(RuntimeMode::Beta, 0).is_err());
        assert!(stub_analysis(RuntimeMode::Mainnet, 0).is_err());
    }
}
