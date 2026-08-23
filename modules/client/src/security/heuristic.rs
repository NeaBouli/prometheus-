//! Development-only structural triage heuristic.
//!
//! This module is a callable library foundation only. It is not wired into any
//! runtime, scanner, or rule-sync path, and it carries no detection, malware,
//! quarantine, or production authority. It never labels content malicious and
//! never claims or grants quarantine authorization.
//!
//! The only caller input is the exact byte slice passed to [`triage_bytes`].
//! There is no path, process, or API monitoring. Input is strictly bounded at
//! 16 MiB; empty and oversized inputs fail closed with an error.
//!
//! The triage score is a deterministic integer in basis points (0..=10000)
//! computed from a fixed set of bounded, explainable structural signals. The
//! caller cannot supply a score or reason codes; both are derived internally
//! from the bytes alone. The report carries the SHA-256 digest and length of
//! the exact input bytes for correlation.

use anyhow::Result;
use sha2::{Digest, Sha256};

/// Strict maximum input size: 16 MiB. Inputs larger than this fail closed.
pub const MAX_INPUT_LEN: usize = 16 * 1024 * 1024;

/// Maximum triage score in basis points (100.00%).
pub const MAX_SCORE_BP: u16 = 10_000;

/// Weight in basis points for [`TriageReason::ExecutableMagicAtStart`].
pub const WEIGHT_EXECUTABLE_MAGIC_AT_START_BP: u16 = 4_000;
/// Weight in basis points for [`TriageReason::EmbeddedExecutableMagic`].
pub const WEIGHT_EMBEDDED_EXECUTABLE_MAGIC_BP: u16 = 2_000;
/// Weight in basis points for [`TriageReason::HighByteDiversity`].
pub const WEIGHT_HIGH_BYTE_DIVERSITY_BP: u16 = 2_000;
/// Weight in basis points for [`TriageReason::HighNullByteDensity`].
pub const WEIGHT_HIGH_NULL_BYTE_DENSITY_BP: u16 = 1_500;
/// Weight in basis points for [`TriageReason::HighNonPrintableDensity`].
pub const WEIGHT_HIGH_NON_PRINTABLE_DENSITY_BP: u16 = 1_500;
/// Weight in basis points for [`TriageReason::LongUniformRun`].
pub const WEIGHT_LONG_UNIFORM_RUN_BP: u16 = 500;

/// Distinct byte value count at or above which
/// [`TriageReason::HighByteDiversity`] fires. This is a coarse structural
/// proxy for packed or compressed regions, not an entropy claim.
const BYTE_DIVERSITY_THRESHOLD: usize = 200;

/// Null byte density above which [`TriageReason::HighNullByteDensity`]
/// fires, expressed as the integer ratio 1/4 (more than 25%).
const NULL_DENSITY_NUMERATOR: usize = 1;
const NULL_DENSITY_DENOMINATOR: usize = 4;

/// Non-printable byte density above which
/// [`TriageReason::HighNonPrintableDensity`] fires, expressed as the integer
/// ratio 3/5 (more than 60%).
const NON_PRINTABLE_NUMERATOR: usize = 3;
const NON_PRINTABLE_DENOMINATOR: usize = 5;

/// Single-byte run length at or above which [`TriageReason::LongUniformRun`]
/// fires.
const UNIFORM_RUN_THRESHOLD: usize = 4096;

/// Fixed structural reason codes explaining a triage score.
///
/// These codes describe byte structure only. None of them means "malicious",
/// and none of them authorizes any action. The set is closed; callers cannot
/// contribute reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TriageReason {
    /// Input begins with a recognized executable or script magic
    /// (`MZ`, `\x7fELF`, a Mach-O magic, or a `#!` shebang).
    ExecutableMagicAtStart,
    /// A recognized executable or script magic appears at an offset
    /// greater than zero.
    EmbeddedExecutableMagic,
    /// At least 200 distinct byte values occur (structural proxy for
    /// packed or compressed content; not an entropy claim).
    HighByteDiversity,
    /// More than 25% of the input bytes are zero.
    HighNullByteDensity,
    /// More than 60% of the input bytes are outside the printable ASCII
    /// set (space..tilde plus tab, CR, LF).
    HighNonPrintableDensity,
    /// A single byte value repeats for at least 4096 consecutive bytes.
    LongUniformRun,
}

impl TriageReason {
    /// Fixed basis-point weight of this reason.
    pub const fn weight_bp(self) -> u16 {
        match self {
            Self::ExecutableMagicAtStart => WEIGHT_EXECUTABLE_MAGIC_AT_START_BP,
            Self::EmbeddedExecutableMagic => WEIGHT_EMBEDDED_EXECUTABLE_MAGIC_BP,
            Self::HighByteDiversity => WEIGHT_HIGH_BYTE_DIVERSITY_BP,
            Self::HighNullByteDensity => WEIGHT_HIGH_NULL_BYTE_DENSITY_BP,
            Self::HighNonPrintableDensity => WEIGHT_HIGH_NON_PRINTABLE_DENSITY_BP,
            Self::LongUniformRun => WEIGHT_LONG_UNIFORM_RUN_BP,
        }
    }
}

/// Deterministic structural triage outcome for one exact byte input.
///
/// This report is descriptive only. It is not a detection verdict, it does
/// not identify malware, and it does not authorize quarantine or any other
/// action. Contains no caller-supplied fields: every field is derived
/// internally from the exact input bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageReport {
    /// Triage score in basis points, capped at [`MAX_SCORE_BP`].
    pub score_bp: u16,
    /// Structural reason codes behind the score, in fixed evaluation order.
    /// Empty when no signal fired.
    pub reasons: Vec<TriageReason>,
    /// SHA-256 digest of the exact input bytes.
    pub sha256: [u8; 32],
    /// Length of the exact input bytes.
    pub input_len: usize,
}

/// Recognized executable/script magic prefixes, checked at offset zero and
/// (for the embedded signal) at any later offset.
const MAGIC_PREFIXES: &[&[u8]] = &[
    b"MZ",
    b"\x7fELF",
    b"#!",
    // Mach-O 32/64-bit, both endiannesses.
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
];

/// Compute the deterministic structural triage report for exact
/// caller-supplied bytes.
///
/// Fails closed: empty input and input larger than [`MAX_INPUT_LEN`] are
/// rejected with an error. The computation uses integer arithmetic only and
/// is fully deterministic for identical input bytes.
pub fn triage_bytes(data: &[u8]) -> Result<TriageReport> {
    if data.is_empty() {
        anyhow::bail!("heuristic input must not be empty");
    }
    if data.len() > MAX_INPUT_LEN {
        anyhow::bail!("heuristic input exceeds the 16 MiB limit");
    }

    let sha256 = Sha256::digest(data).into();
    let mut reasons = Vec::new();

    if starts_with_magic(data) {
        reasons.push(TriageReason::ExecutableMagicAtStart);
    }
    if has_embedded_magic(data) {
        reasons.push(TriageReason::EmbeddedExecutableMagic);
    }

    let mut distinct = [false; 256];
    let mut null_count = 0usize;
    let mut non_printable_count = 0usize;
    let mut max_run = 0usize;
    let mut current_run = 0usize;
    let mut previous_byte = None;

    for &byte in data {
        distinct[byte as usize] = true;
        if byte == 0 {
            null_count += 1;
        }
        if !is_printable(byte) {
            non_printable_count += 1;
        }
        if previous_byte == Some(byte) {
            current_run += 1;
        } else {
            current_run = 1;
            previous_byte = Some(byte);
        }
        if current_run > max_run {
            max_run = current_run;
        }
    }

    let distinct_count = distinct.iter().filter(|&&seen| seen).count();
    if distinct_count >= BYTE_DIVERSITY_THRESHOLD {
        reasons.push(TriageReason::HighByteDiversity);
    }
    // Integer density comparisons: fires only when strictly above the ratio.
    if null_count * NULL_DENSITY_DENOMINATOR > data.len() * NULL_DENSITY_NUMERATOR {
        reasons.push(TriageReason::HighNullByteDensity);
    }
    if non_printable_count * NON_PRINTABLE_DENOMINATOR > data.len() * NON_PRINTABLE_NUMERATOR {
        reasons.push(TriageReason::HighNonPrintableDensity);
    }
    if max_run >= UNIFORM_RUN_THRESHOLD {
        reasons.push(TriageReason::LongUniformRun);
    }

    let score_bp = reasons
        .iter()
        .fold(0u32, |acc, reason| acc + u32::from(reason.weight_bp()))
        .min(u32::from(MAX_SCORE_BP)) as u16;

    Ok(TriageReport {
        score_bp,
        reasons,
        sha256,
        input_len: data.len(),
    })
}

/// Whether the input starts with any recognized magic prefix.
fn starts_with_magic(data: &[u8]) -> bool {
    MAGIC_PREFIXES.iter().any(|magic| data.starts_with(magic))
}

/// Whether any recognized magic prefix occurs at an offset greater than zero.
/// Bounded by the 16 MiB input limit already enforced by the caller.
fn has_embedded_magic(data: &[u8]) -> bool {
    data.iter()
        .enumerate()
        .skip(1)
        .any(|(offset, byte)| match byte {
            b'M' => data[offset..].starts_with(b"MZ"),
            0x7f => data[offset..].starts_with(b"\x7fELF"),
            b'#' => data[offset..].starts_with(b"#!"),
            0xfe | 0xce | 0xcf => MAGIC_PREFIXES[3..]
                .iter()
                .any(|magic| data[offset..].starts_with(magic)),
            _ => false,
        })
}

/// Whether a byte is in the printable set: space..tilde plus tab, CR, LF.
const fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_empty_input_fail_closed() {
        assert!(triage_bytes(b"").is_err());
    }

    #[test]
    fn test_rejects_oversized_input_fail_closed() {
        let data = vec![0u8; MAX_INPUT_LEN + 1];
        assert!(triage_bytes(&data).is_err());
    }

    #[test]
    fn test_accepts_exactly_max_input_boundary() {
        let data = vec![b'a'; MAX_INPUT_LEN];
        let report = triage_bytes(&data).unwrap();
        assert_eq!(report.input_len, MAX_INPUT_LEN);
        // A uniform 16 MiB run fires exactly one structural signal.
        assert_eq!(report.reasons, vec![TriageReason::LongUniformRun]);
        assert_eq!(report.score_bp, TriageReason::LongUniformRun.weight_bp());
    }

    #[test]
    fn test_plain_text_scores_zero() {
        let report = triage_bytes(b"hello world, this is ordinary printable text.\n").unwrap();
        assert_eq!(report.score_bp, 0);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn test_digest_matches_known_sha256_vector() {
        let report = triage_bytes(b"test").unwrap();
        assert_eq!(
            hex::encode(report.sha256),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(report.input_len, 4);
    }

    #[test]
    fn test_executable_magic_at_start() {
        for prefix in [b"MZ" as &[u8], b"\x7fELF", b"#!", b"\xfe\xed\xfa\xce"] {
            let mut data = prefix.to_vec();
            data.extend_from_slice(b" printable trailer text");
            let report = triage_bytes(&data).unwrap();
            assert!(report
                .reasons
                .contains(&TriageReason::ExecutableMagicAtStart));
            assert!(!report
                .reasons
                .contains(&TriageReason::EmbeddedExecutableMagic));
            assert!(report.score_bp >= WEIGHT_EXECUTABLE_MAGIC_AT_START_BP);
        }
    }

    #[test]
    fn test_embedded_magic_beyond_offset_zero() {
        let data = b"printable header text \x7fELF printable trailer text";
        let report = triage_bytes(data).unwrap();
        assert!(!report
            .reasons
            .contains(&TriageReason::ExecutableMagicAtStart));
        assert!(report
            .reasons
            .contains(&TriageReason::EmbeddedExecutableMagic));
    }

    #[test]
    fn test_magic_at_last_possible_offset_not_missed() {
        let mut data = b"printable header text".to_vec();
        data.extend_from_slice(b"MZ");
        let report = triage_bytes(&data).unwrap();
        assert!(report
            .reasons
            .contains(&TriageReason::EmbeddedExecutableMagic));
    }

    #[test]
    fn test_single_byte_input_no_panic() {
        let report = triage_bytes(b"A").unwrap();
        assert_eq!(report.score_bp, 0);
        assert_eq!(report.input_len, 1);
        // A leading byte equal to the first byte of a magic is not a match.
        let report = triage_bytes(b"M").unwrap();
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn test_high_byte_diversity() {
        let mut data = Vec::new();
        for _ in 0..2 {
            data.extend(0u8..=255);
        }
        // Mostly non-printable by construction; check the diversity reason.
        let report = triage_bytes(&data).unwrap();
        assert!(report.reasons.contains(&TriageReason::HighByteDiversity));
    }

    #[test]
    fn test_low_byte_diversity_does_not_fire() {
        let data = b"ab".repeat(512);
        let report = triage_bytes(&data).unwrap();
        assert!(!report.reasons.contains(&TriageReason::HighByteDiversity));
    }

    #[test]
    fn test_null_density_boundary() {
        // Exactly 25% null bytes must NOT fire (strictly-greater rule).
        let mut data = vec![0u8; 100];
        data.extend(std::iter::repeat_n(b'x', 300));
        let report = triage_bytes(&data).unwrap();
        assert!(!report.reasons.contains(&TriageReason::HighNullByteDensity));

        // Just above 25% must fire.
        let mut data = vec![0u8; 101];
        data.extend(std::iter::repeat_n(b'x', 299));
        let report = triage_bytes(&data).unwrap();
        assert!(report.reasons.contains(&TriageReason::HighNullByteDensity));
    }

    #[test]
    fn test_non_printable_density_boundary() {
        // Exactly 60% non-printable must NOT fire.
        let mut data = vec![0x01u8; 60];
        data.extend(std::iter::repeat_n(b'x', 40));
        let report = triage_bytes(&data).unwrap();
        assert!(!report
            .reasons
            .contains(&TriageReason::HighNonPrintableDensity));

        // Just above 60% must fire.
        let mut data = vec![0x01u8; 61];
        data.extend(std::iter::repeat_n(b'x', 39));
        let report = triage_bytes(&data).unwrap();
        assert!(report
            .reasons
            .contains(&TriageReason::HighNonPrintableDensity));
    }

    #[test]
    fn test_long_uniform_run_boundary() {
        let mut data = vec![b'x'; UNIFORM_RUN_THRESHOLD - 1];
        data.insert(0, b'y');
        let report = triage_bytes(&data).unwrap();
        assert!(!report.reasons.contains(&TriageReason::LongUniformRun));

        let mut data = vec![b'x'; UNIFORM_RUN_THRESHOLD];
        data.insert(0, b'y');
        let report = triage_bytes(&data).unwrap();
        assert!(report.reasons.contains(&TriageReason::LongUniformRun));
    }

    #[test]
    fn test_score_capped_at_max() {
        // Craft an input that fires every signal: raw weight sum is 11500 bp.
        let mut data = Vec::new();
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(b"\x7fELF");
        for _ in 0..8 {
            data.extend(0u8..=255);
        }
        data.extend(std::iter::repeat_n(0u8, 3000));
        data.extend(std::iter::repeat_n(0xAAu8, UNIFORM_RUN_THRESHOLD));
        let report = triage_bytes(&data).unwrap();
        assert_eq!(report.reasons.len(), 6);
        assert_eq!(report.score_bp, MAX_SCORE_BP);
    }

    #[test]
    fn test_reasons_in_fixed_order_and_weights_sum_to_score() {
        let mut data = Vec::new();
        data.extend_from_slice(b"#!");
        for _ in 0..2 {
            data.extend(0u8..=255);
        }
        data.extend(std::iter::repeat_n(0u8, 2000));
        data.extend(std::iter::repeat_n(0xBBu8, UNIFORM_RUN_THRESHOLD));
        let report = triage_bytes(&data).unwrap();
        let mut sorted = report.reasons.clone();
        sorted.sort();
        assert_eq!(report.reasons, sorted);
        let raw: u32 = report
            .reasons
            .iter()
            .map(|reason| u32::from(reason.weight_bp()))
            .sum();
        assert_eq!(u32::from(report.score_bp), raw.min(u32::from(MAX_SCORE_BP)));
    }

    #[test]
    fn test_determinism_identical_inputs_identical_reports() {
        let mut data = b"MZ deterministic probe \x7fELF".to_vec();
        data.extend(0u8..=255);
        data.extend(std::iter::repeat_n(0u8, 5000));
        let first = triage_bytes(&data).unwrap();
        let second = triage_bytes(&data).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_single_bit_flip_changes_digest_but_not_structure() {
        let data = vec![b'q'; 1024];
        let mut flipped = data.clone();
        flipped[512] = b'p';
        let a = triage_bytes(&data).unwrap();
        let b = triage_bytes(&flipped).unwrap();
        assert_ne!(a.sha256, b.sha256);
        assert_eq!(a.score_bp, b.score_bp);
        assert_eq!(a.reasons, b.reasons);
    }

    #[test]
    fn test_report_is_descriptive_not_a_verdict() {
        // Even a maximum score report carries no malicious/quarantine claim:
        // the API surface exposes only score, reason codes, digest and length.
        let mut data = Vec::new();
        data.extend_from_slice(b"MZ");
        for _ in 0..8 {
            data.extend(0u8..=255);
        }
        data.extend(std::iter::repeat_n(0u8, 6000));
        let report = triage_bytes(&data).unwrap();
        let debug = format!("{report:?}");
        let lowered = debug.to_lowercase();
        assert!(!lowered.contains("malicious"));
        assert!(!lowered.contains("quarantine"));
        assert!(!lowered.contains("threat"));
    }
}
