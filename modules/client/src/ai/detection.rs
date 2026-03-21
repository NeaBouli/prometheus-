//! Anomaly detection module combining YARA scanning and Phi-3-mini AI analysis.
//!
//! Produces a final verdict by correlating rule-based and AI-based detection.
//! Verdict logic:
//! - YARA match AND AI confidence > 0.85 → Threat
//! - YARA match OR AI confidence > 0.5 → Suspicious
//! - Otherwise → Clean
//!
//! Reports are only generated when confidence exceeds MIN_CONFIDENCE_KI (0.85).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::phi3::{AiAnalysis, Phi3Model, MIN_CONFIDENCE_KI};
use crate::security::scanner::{ScanResult, YaraScanner};

/// Confidence threshold for classifying as Suspicious
const SUSPICIOUS_THRESHOLD: f64 = 0.5;

/// Final detection result combining YARA and AI analysis.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// SHA-256 hash of the scanned content
    pub file_hash: [u8; 32],
    /// YARA scanner result
    pub yara_result: ScanResult,
    /// Phi-3-mini AI analysis result
    pub ai_analysis: AiAnalysis,
    /// Combined verdict
    pub final_verdict: Verdict,
    /// Whether this should be reported to the network (confidence > 0.85)
    pub should_report: bool,
}

/// Combined threat verdict from YARA + AI analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// No threat detected
    Clean,
    /// Possible threat, needs further investigation
    Suspicious,
    /// Confirmed threat by both YARA and AI
    Threat,
}

/// Anomaly detector combining YARA pattern matching and Phi-3-mini AI.
/// Uses tokio::sync::Mutex for async safety (PATTERN-003).
pub struct AnomalyDetector {
    model: Arc<Mutex<Phi3Model>>,
    scanner: Arc<Mutex<YaraScanner>>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with the given AI model and YARA scanner.
    pub fn new(model: Arc<Mutex<Phi3Model>>, scanner: Arc<Mutex<YaraScanner>>) -> Self {
        Self { model, scanner }
    }

    /// Analyze a file at the given path using both YARA and AI.
    pub async fn analyze_file(&self, path: &Path) -> Result<DetectionResult> {
        let data = tokio::fs::read(path)
            .await
            .context("Failed to read file for analysis")?;
        self.analyze_bytes(&data).await
    }

    /// Analyze raw bytes using both YARA and AI.
    pub async fn analyze_bytes(&self, data: &[u8]) -> Result<DetectionResult> {
        let file_hash = compute_hash(data);

        // Run YARA scan
        let yara_result = {
            let scanner = self.scanner.lock().await;
            scanner.scan_bytes(data)?
        };

        // Run AI analysis
        let ai_analysis = {
            let model = self.model.lock().await;
            model.analyze_bytes(data).await?
        };

        // Determine verdict
        let final_verdict = determine_verdict(yara_result.is_threat, ai_analysis.confidence);

        // Only report if confidence exceeds MIN_CONFIDENCE_KI (0.85)
        let should_report = ai_analysis.confidence > MIN_CONFIDENCE_KI;

        Ok(DetectionResult {
            file_hash,
            yara_result,
            ai_analysis,
            final_verdict,
            should_report,
        })
    }
}

/// Determine the final verdict based on YARA and AI results.
/// - YARA match AND AI confidence > 0.85 → Threat
/// - YARA match OR AI confidence > 0.5 → Suspicious
/// - Otherwise → Clean
fn determine_verdict(yara_match: bool, ai_confidence: f64) -> Verdict {
    if yara_match && ai_confidence > MIN_CONFIDENCE_KI {
        Verdict::Threat
    } else if yara_match || ai_confidence > SUSPICIOUS_THRESHOLD {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

/// Compute SHA-256 hash of data.
fn compute_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::scanner::CompiledRule;
    use std::path::PathBuf;

    async fn make_detector(rules: Vec<CompiledRule>) -> AnomalyDetector {
        let model = Phi3Model::new(&PathBuf::from("/nonexistent/model.onnx")).unwrap();
        let mut scanner = YaraScanner::new().unwrap();
        for rule in rules {
            scanner.add_rule(rule);
        }
        AnomalyDetector::new(Arc::new(Mutex::new(model)), Arc::new(Mutex::new(scanner)))
    }

    fn eicar_rule() -> CompiledRule {
        CompiledRule {
            name: "EICAR".to_string(),
            patterns: vec![b"EICAR".to_vec()],
            required_matches: 1,
        }
    }

    #[test]
    fn test_verdict_clean() {
        assert_eq!(determine_verdict(false, 0.0), Verdict::Clean);
        assert_eq!(determine_verdict(false, 0.3), Verdict::Clean);
        assert_eq!(determine_verdict(false, 0.5), Verdict::Clean);
    }

    #[test]
    fn test_verdict_suspicious_yara_only() {
        assert_eq!(determine_verdict(true, 0.0), Verdict::Suspicious);
        assert_eq!(determine_verdict(true, 0.5), Verdict::Suspicious);
        assert_eq!(determine_verdict(true, 0.84), Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_suspicious_ai_only() {
        assert_eq!(determine_verdict(false, 0.51), Verdict::Suspicious);
        assert_eq!(determine_verdict(false, 0.7), Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_threat() {
        assert_eq!(determine_verdict(true, 0.86), Verdict::Threat);
        assert_eq!(determine_verdict(true, 1.0), Verdict::Threat);
    }

    #[tokio::test]
    async fn test_analyze_clean_data() {
        let detector = make_detector(vec![eicar_rule()]).await;
        let result = detector.analyze_bytes(b"clean data here").await.unwrap();
        assert_eq!(result.final_verdict, Verdict::Clean);
        assert!(!result.should_report);
    }

    #[tokio::test]
    async fn test_analyze_yara_match_no_ai() {
        // YARA matches but AI model not loaded → Suspicious (not Threat)
        let detector = make_detector(vec![eicar_rule()]).await;
        let result = detector
            .analyze_bytes(b"file contains EICAR test")
            .await
            .unwrap();
        assert_eq!(result.final_verdict, Verdict::Suspicious);
        assert!(!result.should_report); // AI confidence = 0.0 < 0.85
    }

    #[tokio::test]
    async fn test_should_report_threshold() {
        // Without model, confidence is always 0.0 → should_report = false
        let detector = make_detector(vec![]).await;
        let result = detector.analyze_bytes(b"anything").await.unwrap();
        assert!(!result.should_report);
    }

    #[tokio::test]
    async fn test_file_hash_computed() {
        let detector = make_detector(vec![]).await;
        let data = b"test data";
        let result = detector.analyze_bytes(data).await.unwrap();
        assert_eq!(result.file_hash, compute_hash(data));
    }

    #[test]
    fn test_min_confidence_value() {
        // Verify the threshold matches MEMO.md
        assert!((MIN_CONFIDENCE_KI - 0.85).abs() < f64::EPSILON);
    }
}
