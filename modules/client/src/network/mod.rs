/// The GH-226 v1 ThreatHint sender is Unix-only because
/// `prometheus-guardian-p2p` requires Unix AF_UNIX and peer credentials.
#[cfg(unix)]
pub mod p2p;
pub mod threat_hint;
pub mod zk_proof;
