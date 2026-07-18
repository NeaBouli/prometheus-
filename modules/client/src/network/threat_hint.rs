use crate::network::zk_proof::ZkProof;
use crate::runtime::{require_stub_allowed_for, RuntimeMode};
use anyhow::{bail, Context, Result};
use prometheus_threat_hint::{
    ThreatHintEnvelope, ThreatIndicatorType, ThreatProofSystem, MAX_PROOF_BYTES,
};

pub type IndicatorType = ThreatIndicatorType;
pub use ThreatProofSystem::{DevelopmentStubV1, Groth16Kip16V1};

pub const CONFIDENCE_BPS_SCALE: f64 = 10_000.0;

/// Build a canonical threat hint envelope from a report input tuple.
///
/// - confidence is checked for finiteness and bounded in `0.0..=1.0`
/// - proof confidence is mapped using floor (`x * 10_000.0`).
/// - `ZkProof.public_input` must equal `threat_hash`
/// - proof bytes must be 1..=1024
/// - stubs are only allowed in development mode
/// - Groth16/KIP-16 proofs are accepted as opaque bytes; no Groth16 verification is
///   performed in this builder.
pub struct ThreatHintBuilder {
    threat_hash: [u8; 32],
    confidence: f64,
    indicator_type: ThreatIndicatorType,
    proof: ZkProof,
    report_nonce: [u8; 32],
    observed_at: u64,
}

impl ThreatHintBuilder {
    pub fn new(
        threat_hash: [u8; 32],
        confidence: f64,
        indicator_type: ThreatIndicatorType,
        proof: ZkProof,
        report_nonce: [u8; 32],
        observed_at: u64,
    ) -> Self {
        Self {
            threat_hash,
            confidence,
            indicator_type,
            proof,
            report_nonce,
            observed_at,
        }
    }

    pub fn build(&self) -> Result<ThreatHintEnvelope> {
        self.build_with_mode(RuntimeMode::from_env())
    }

    pub fn build_with_mode(&self, mode: RuntimeMode) -> Result<ThreatHintEnvelope> {
        self.validate_input()?;

        let proof_system = if self.proof.is_stub {
            require_stub_allowed_for(mode, "ThreatHint proof")?;
            DevelopmentStubV1
        } else {
            // No Groth16 verification is performed here; this path intentionally
            // accepts opaque proof bytes and leaves cryptographic validation to
            // downstream verifiers.
            Groth16Kip16V1
        };

        let confidence_bps = (self.confidence * CONFIDENCE_BPS_SCALE).floor() as u16;

        ThreatHintEnvelope::new(
            hex::encode(self.threat_hash),
            confidence_bps,
            self.indicator_type,
            proof_system,
            self.proof.proof_data.clone(),
            hex::encode(self.report_nonce),
            self.observed_at,
        )
        .context("failed to build threat hint envelope")
    }

    fn validate_input(&self) -> Result<()> {
        if !self.confidence.is_finite() {
            bail!("invalid threat confidence")
        }

        if !(0.0 < self.confidence && self.confidence <= 1.0) {
            bail!("confidence out of range")
        }

        if self.proof.public_input != self.threat_hash {
            bail!("proof public input does not match threat hash")
        }

        if self.proof.proof_data.is_empty() || self.proof.proof_data.len() > MAX_PROOF_BYTES {
            bail!("invalid proof payload")
        }

        if self.observed_at == 0 {
            bail!("invalid observed_at")
        }

        Ok(())
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<ThreatHintEnvelope> {
        ThreatHintEnvelope::parse_canonical(bytes)
            .context("failed to parse canonical threat hint envelope")
    }

    pub fn to_canonical(env: &ThreatHintEnvelope) -> Result<Vec<u8>> {
        env.to_canonical_bytes()
            .context("failed to serialize canonical threat hint envelope")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_generator_stubs() -> ZkProof {
        ZkProof {
            proof_data: vec![0x42u8; 1],
            public_input: [0x42u8; 32],
            is_stub: true,
        }
    }

    #[test]
    fn development_stub_success() {
        let mut proof = mk_generator_stubs();
        proof.public_input = [0x42u8; 32];
        let builder = ThreatHintBuilder::new(
            [0x42u8; 32],
            0.91,
            ThreatIndicatorType::FileHash,
            proof,
            [0x24u8; 32],
            1_700_000_000,
        );

        let envelope = builder.build_with_mode(RuntimeMode::Development).unwrap();
        assert_eq!(envelope.proof_system(), DevelopmentStubV1);
        assert_eq!(envelope.confidence_bps(), 9100);
        assert_eq!(envelope.threat_hash(), hex::encode([0x42u8; 32]));
        assert_eq!(envelope.report_nonce(), hex::encode([0x24u8; 32]));
    }

    #[test]
    fn beta_and_mainnet_stub_rejected() {
        for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
            let mut proof = mk_generator_stubs();
            proof.is_stub = true;
            let builder = ThreatHintBuilder::new(
                [0x42u8; 32],
                0.5,
                ThreatIndicatorType::Behavior,
                proof,
                [0x11u8; 32],
                1_700_000_000,
            );

            assert!(builder.build_with_mode(mode).is_err());
        }
    }

    #[test]
    fn hash_mismatch_fails() {
        let proof = ZkProof {
            proof_data: vec![1u8; 3],
            public_input: [0x11u8; 32],
            is_stub: true,
        };
        let builder = ThreatHintBuilder::new(
            [0x42u8; 32],
            0.6,
            ThreatIndicatorType::Network,
            proof,
            [0x11u8; 32],
            1,
        );

        assert!(builder.build_with_mode(RuntimeMode::Development).is_err());
    }

    #[test]
    fn confidence_validation_rejects_nonfinite_or_out_of_range() {
        for confidence in [f64::NAN, f64::INFINITY, -0.1, 0.0, 1.1] {
            let builder = ThreatHintBuilder::new(
                [0x99u8; 32],
                confidence,
                ThreatIndicatorType::ApiCall,
                mk_generator_stubs(),
                [0x33u8; 32],
                1,
            );

            assert!(builder.build_with_mode(RuntimeMode::Development).is_err());
        }
    }

    #[test]
    fn confidence_floor_is_conservative_bps() {
        let proof = ZkProof {
            proof_data: vec![0x77u8; 2],
            public_input: [0x01u8; 32],
            is_stub: true,
        };
        let builder = ThreatHintBuilder::new(
            [0x01u8; 32],
            0.8599,
            ThreatIndicatorType::FileHash,
            proof,
            [0x77u8; 32],
            1,
        );

        assert_eq!(
            builder
                .build_with_mode(RuntimeMode::Development)
                .unwrap()
                .confidence_bps(),
            8599
        );
    }

    #[test]
    fn zero_timestamp_rejected() {
        let proof = mk_generator_stubs();
        let builder = ThreatHintBuilder::new(
            [0x01u8; 32],
            0.7,
            ThreatIndicatorType::FileHash,
            proof,
            [0x55u8; 32],
            0,
        );

        assert!(builder.build_with_mode(RuntimeMode::Development).is_err());
    }

    #[test]
    fn canonical_parse_roundtrip() {
        let proof = ZkProof {
            proof_data: vec![3u8; 10],
            public_input: [0x77u8; 32],
            is_stub: false,
        };

        let builder = ThreatHintBuilder::new(
            [0x77u8; 32],
            0.72,
            ThreatIndicatorType::Behavior,
            proof,
            [0x22u8; 32],
            1_700_000_000,
        );

        let envelope = builder.build_with_mode(RuntimeMode::Development).unwrap();
        let canonical = ThreatHintBuilder::to_canonical(&envelope).unwrap();
        let parsed = ThreatHintBuilder::parse_canonical(&canonical).unwrap();
        assert_eq!(envelope, parsed);
    }

    #[test]
    fn non_stub_does_not_verify_groth16() {
        let proof = ZkProof {
            proof_data: vec![1u8; 2],
            public_input: [0x88u8; 32],
            is_stub: false,
        };
        let builder = ThreatHintBuilder::new(
            [0x88u8; 32],
            0.8,
            ThreatIndicatorType::FileHash,
            proof,
            [0x09u8; 32],
            1,
        );

        let envelope = builder.build_with_mode(RuntimeMode::Development).unwrap();
        assert_eq!(envelope.proof_system(), Groth16Kip16V1);
    }
}
