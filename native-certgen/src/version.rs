/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Version resolution tables for KeyMint / legacy Keymaster backends.
//!
//! `KeyMintVersionResolver` on the Kotlin side keeps the binder plumbing: it looks the service up
//! through `ServiceManager`, calls `IKeyMintDevice.interfaceVersion`, or hand-rolls the compat
//! `Parcel` transaction. Everything that turns a *number* into an *attestation version pair* lives
//! here, so the mapping tables have exactly one owner and can be unit-tested off-device.
//!
//! Wire format returned to Kotlin: eight bytes, `[i32 attestation][i32 keymaster]`, both big-endian.
//! A `None` result is exported as a `null` byte array rather than a sentinel pair, because every
//! value in the pair is a legitimate version number.

/// `android.hardware.security.keymint.SecurityLevel.TRUSTED_ENVIRONMENT`.
pub const SECURITY_LEVEL_TRUSTED_ENVIRONMENT: i32 = 1;
/// `android.hardware.security.keymint.SecurityLevel.STRONGBOX`.
pub const SECURITY_LEVEL_STRONGBOX: i32 = 2;

/// One resolved attestation/keymaster version pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationVersions {
    pub attestation: i32,
    pub keymaster: i32,
}

impl AttestationVersions {
    pub const fn new(attestation: i32, keymaster: i32) -> Self {
        Self {
            attestation,
            keymaster,
        }
    }

    /// Big-endian wire form: `[i32 attestation][i32 keymaster]`.
    pub fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.attestation.to_be_bytes());
        out[4..8].copy_from_slice(&self.keymaster.to_be_bytes());
        out
    }

    /// Inverse of [`Self::encode`]. Rejects anything that is not exactly eight bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let body: [u8; 8] = bytes.try_into().ok()?;
        let mut attestation = [0u8; 4];
        let mut keymaster = [0u8; 4];
        attestation.copy_from_slice(&body[0..4]);
        keymaster.copy_from_slice(&body[4..8]);
        Some(Self {
            attestation: i32::from_be_bytes(attestation),
            keymaster: i32::from_be_bytes(keymaster),
        })
    }
}

/// Binder service instance name for the KeyMint HAL, or `None` for levels KeyMint does not serve.
pub fn keymint_instance(security_level: i32) -> Option<&'static str> {
    match security_level {
        SECURITY_LEVEL_TRUSTED_ENVIRONMENT => Some("default"),
        SECURITY_LEVEL_STRONGBOX => Some("strongbox"),
        _ => None,
    }
}

/// Maps a KeyMint `interfaceVersion` to the pair reported in attestation records.
///
/// KeyMint numbers its AIDL interface `1`, `2`, `3`, ... while the attestation version is the same
/// number scaled by 100. A non-positive interface version means the service did not report one and
/// must not be turned into a version pair.
pub fn versions_from_interface_version(interface_version: i32) -> Option<AttestationVersions> {
    if interface_version <= 0 {
        return None;
    }
    let version = interface_version.checked_mul(100)?;
    Some(AttestationVersions::new(version, version))
}

/// Maps a legacy Keymaster `hardwareInfo.versionNumber` to the pair it argues for.
///
/// These are the only four numbers the platform ever emitted; anything else is a backend we do not
/// know how to describe, and the caller falls back to the cached/assumed path.
pub fn legacy_keymaster_versions(version_number: i32) -> Option<AttestationVersions> {
    match version_number {
        20 => Some(AttestationVersions::new(1, 2)),
        30 => Some(AttestationVersions::new(2, 3)),
        40 => Some(AttestationVersions::new(3, 4)),
        41 => Some(AttestationVersions::new(4, 41)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_match_security_levels() {
        assert_eq!(
            keymint_instance(SECURITY_LEVEL_TRUSTED_ENVIRONMENT),
            Some("default")
        );
        assert_eq!(
            keymint_instance(SECURITY_LEVEL_STRONGBOX),
            Some("strongbox")
        );
    }

    #[test]
    fn unknown_security_levels_have_no_instance() {
        for level in [0, 3, 4, -1, i32::MAX, i32::MIN] {
            assert_eq!(keymint_instance(level), None, "level {level}");
        }
    }

    #[test]
    fn interface_version_scales_by_one_hundred() {
        assert_eq!(
            versions_from_interface_version(1),
            Some(AttestationVersions::new(100, 100))
        );
        assert_eq!(
            versions_from_interface_version(2),
            Some(AttestationVersions::new(200, 200))
        );
        assert_eq!(
            versions_from_interface_version(3),
            Some(AttestationVersions::new(300, 300))
        );
    }

    #[test]
    fn non_positive_interface_versions_are_rejected() {
        assert_eq!(versions_from_interface_version(0), None);
        assert_eq!(versions_from_interface_version(-1), None);
        assert_eq!(versions_from_interface_version(i32::MIN), None);
    }

    #[test]
    fn interface_version_overflow_is_rejected() {
        // 100 * 21_474_837 overflows i32; the resolver must report "unknown" instead of wrapping.
        assert_eq!(versions_from_interface_version(i32::MAX / 100 + 1), None);
        assert_eq!(versions_from_interface_version(i32::MAX), None);
    }

    #[test]
    fn legacy_table_covers_every_known_backend() {
        assert_eq!(
            legacy_keymaster_versions(20),
            Some(AttestationVersions::new(1, 2))
        );
        assert_eq!(
            legacy_keymaster_versions(30),
            Some(AttestationVersions::new(2, 3))
        );
        assert_eq!(
            legacy_keymaster_versions(40),
            Some(AttestationVersions::new(3, 4))
        );
        assert_eq!(
            legacy_keymaster_versions(41),
            Some(AttestationVersions::new(4, 41))
        );
    }

    #[test]
    fn legacy_table_rejects_unknown_backends() {
        for number in [0, 1, 10, 21, 31, 42, 100, -20, i32::MIN, i32::MAX] {
            assert_eq!(legacy_keymaster_versions(number), None, "number {number}");
        }
    }

    #[test]
    fn keymaster_forty_one_keeps_its_raw_number() {
        // Keymaster 4.1 is the one entry where the pair is not simply `(n, n + 1)`.
        let versions = legacy_keymaster_versions(41).expect("41 is supported");
        assert_eq!(versions.attestation, 4);
        assert_eq!(versions.keymaster, 41);
        assert_ne!(versions.keymaster, 5);
    }

    #[test]
    fn encode_is_big_endian_and_eight_bytes() {
        let encoded = AttestationVersions::new(1, 2).encode();
        assert_eq!(encoded, [0, 0, 0, 1, 0, 0, 0, 2]);

        let encoded = AttestationVersions::new(4, 41).encode();
        assert_eq!(encoded, [0, 0, 0, 4, 0, 0, 0, 41]);
    }

    #[test]
    fn encode_decode_round_trips() {
        for versions in [
            AttestationVersions::new(0, 0),
            AttestationVersions::new(1, 2),
            AttestationVersions::new(300, 300),
            AttestationVersions::new(-1, -2),
            AttestationVersions::new(i32::MIN, i32::MAX),
        ] {
            assert_eq!(
                AttestationVersions::decode(&versions.encode()),
                Some(versions)
            );
        }
    }

    #[test]
    fn decode_rejects_wrong_lengths() {
        assert_eq!(AttestationVersions::decode(&[]), None);
        assert_eq!(AttestationVersions::decode(&[0; 7]), None);
        assert_eq!(AttestationVersions::decode(&[0; 9]), None);
    }
}
