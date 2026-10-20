//! Read-only PWH5 header inspection. A decoded header is still untrusted:
//! it grants no owner, WAL repair, retained-history, or provenance authority.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct H80Descriptor<'a> {
    pub relative_path: &'a str,
    pub database_id: [u8; 16],
    pub writer_incarnation: [u8; 16],
    pub wal_id: u64,
    pub creation_nonce: [u8; 16],
    pub start_after_sequence: u64,
    pub header_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UntrustedH80 {
    pub database_id: [u8; 16],
    pub writer_incarnation: [u8; 16],
    pub wal_id: u64,
    pub creation_nonce: [u8; 16],
    pub start_after_sequence: u64,
    pub header_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingH80Inspection {
    AbsentPath,
    ExactPrefix(usize),
    Complete(UntrustedH80),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H80Error {
    Corrupt,
    Unsupported,
}

/// Decode exactly one 80-byte header window against a MANIFEST descriptor.
/// For an installed WAL, the caller must separately validate any frames after
/// this window; those bytes are not passed to this function.
pub(crate) fn decode_h80(
    _bytes: &[u8],
    _expected: &H80Descriptor<'_>,
) -> Result<UntrustedH80, H80Error> {
    Err(H80Error::Unsupported)
}

/// Inspect the entire reserved-file image while WalCreate or WalRotate is
/// pending. Only absence, one exact proper header prefix, or H80 alone can
/// match pending state; no frame or other suffix is allowed here.
pub(crate) fn inspect_pending_h80_file(
    _bytes: Option<&[u8]>,
    _expected: &H80Descriptor<'_>,
) -> Result<PendingH80Inspection, H80Error> {
    Err(H80Error::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::{
        H80Descriptor, H80Error, PendingH80Inspection, UntrustedH80, decode_h80,
        inspect_pending_h80_file,
    };

    // Independently reviewed r6 fixed wire vector. Do not produce this from
    // the decoder or its encoder: byte equality is the oracle.
    const GOLDEN_H80: &str = concat!(
        "50574835050050000000000000112233445566778899aabbccddeeff",
        "102132435465768798a9bacbdcedfe0f0100000000000000",
        "0100000000000000a0a1a2a3a4a5a6a70000000000000000bc89bfe1",
    );
    const GOLDEN_DIGEST: &str = "193b67f43552ad15b4c2bbd0ef52a7804a21b6a303f1b0dd04d63302b9bc1faa";
    const GOLDEN_PATH: &str = "wal/00000000000000000001.wal";

    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("fixed hexadecimal")
        })
    }

    fn golden_h80() -> [u8; 80] {
        unhex(GOLDEN_H80)
    }

    fn golden_descriptor() -> H80Descriptor<'static> {
        H80Descriptor {
            relative_path: GOLDEN_PATH,
            database_id: unhex("00112233445566778899aabbccddeeff"),
            writer_incarnation: unhex("102132435465768798a9bacbdcedfe0f"),
            wal_id: 1,
            creation_nonce: unhex("0100000000000000a0a1a2a3a4a5a6a7"),
            start_after_sequence: 0,
            header_digest: unhex(GOLDEN_DIGEST),
        }
    }

    fn golden_decoded() -> UntrustedH80 {
        let expected = golden_descriptor();
        UntrustedH80 {
            database_id: expected.database_id,
            writer_incarnation: expected.writer_incarnation,
            wal_id: expected.wal_id,
            creation_nonce: expected.creation_nonce,
            start_after_sequence: expected.start_after_sequence,
            header_digest: expected.header_digest,
        }
    }

    // Test-only bitwise Castagnoli reference, independent of production's
    // historically misnamed IEEE crate::io::crc32c function.
    fn castagnoli_reference(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
            }
        }
        !crc
    }

    fn digest_reference(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"praxor/wal-header/v5\0");
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    fn refresh_checksums(bytes: &mut [u8; 80], expected: &mut H80Descriptor<'_>) {
        let crc = castagnoli_reference(&bytes[..76]);
        bytes[76..80].copy_from_slice(&crc.to_le_bytes());
        expected.header_digest = digest_reference(bytes);
    }

    fn complete(bytes: &[u8], expected: &H80Descriptor<'_>) -> Result<UntrustedH80, H80Error> {
        decode_h80(bytes, expected)
    }

    fn pending(
        bytes: Option<&[u8]>,
        expected: &H80Descriptor<'_>,
    ) -> Result<PendingH80Inspection, H80Error> {
        inspect_pending_h80_file(bytes, expected)
    }

    #[test]
    fn golden_header_decodes_exact_identity_without_granting_authority() {
        let header = golden_h80();
        assert_eq!(header.len(), 80);
        assert_eq!(
            complete(&header, &golden_descriptor()),
            Ok(golden_decoded())
        );
        assert_eq!(
            pending(Some(&header), &golden_descriptor()),
            Ok(PendingH80Inspection::Complete(golden_decoded()))
        );
    }

    #[test]
    fn pending_accepts_only_absence_or_each_exact_header_prefix() {
        let header = golden_h80();
        let expected = golden_descriptor();
        assert_eq!(
            pending(None, &expected),
            Ok(PendingH80Inspection::AbsentPath)
        );
        for cut in 0..80 {
            assert_eq!(
                pending(Some(&header[..cut]), &expected),
                Ok(PendingH80Inspection::ExactPrefix(cut)),
                "pending header cut {cut}"
            );
        }
        assert_eq!(
            pending(Some(&header), &expected),
            Ok(PendingH80Inspection::Complete(golden_decoded()))
        );
        let mut extra = header.to_vec();
        extra.push(0);
        assert_eq!(pending(Some(&extra), &expected), Err(H80Error::Corrupt));
    }

    #[test]
    fn installed_header_window_requires_all_eighty_bytes_and_no_suffix() {
        let header = golden_h80();
        let expected = golden_descriptor();
        for cut in 0..80 {
            assert_eq!(
                complete(&header[..cut], &expected),
                Err(H80Error::Corrupt),
                "installed header cut {cut}"
            );
        }
        assert_eq!(complete(&header, &expected), Ok(golden_decoded()));
        let mut extra = header.to_vec();
        extra.push(b'P');
        assert_eq!(complete(&extra, &expected), Err(H80Error::Corrupt));
        assert_eq!(
            complete(&extra[..80], &expected),
            Ok(golden_decoded()),
            "an installed WAL can have frames after its header window"
        );
    }

    #[test]
    fn every_visible_wrong_pending_header_byte_is_a_conflict() {
        let header = golden_h80();
        let expected = golden_descriptor();
        for position in 0..80 {
            let mut prefix = header[..=position].to_vec();
            prefix[position] ^= 1;
            assert_eq!(
                pending(Some(&prefix), &expected),
                Err(H80Error::Corrupt),
                "mutated byte {position}"
            );
        }
    }

    #[test]
    fn independent_crc_and_domain_digest_match_the_fixed_golden() {
        let header = golden_h80();
        assert_eq!(castagnoli_reference(b"123456789"), 0xe306_9283);
        assert_eq!(castagnoli_reference(&header[..76]), 0xe1bf_89bc);
        assert_eq!(&header[76..80], &0xe1bf_89bc_u32.to_le_bytes());
        assert_eq!(digest_reference(&header), unhex::<32>(GOLDEN_DIGEST));
        assert_ne!(
            crate::io::crc32c(&header[..76]),
            castagnoli_reference(&header[..76])
        );
    }

    #[test]
    fn checksum_repaired_invalid_fixed_fields_still_refuse() {
        for (name, offset, replacement) in [
            ("magic", 0, b'X'),
            ("v1", 4, 1),
            ("v2", 4, 2),
            ("version high byte", 5, 1),
            ("header length", 6, 79),
            ("header length high byte", 7, 1),
            ("flags", 8, 1),
            ("reserved", 11, 1),
        ] {
            let mut header = golden_h80();
            let mut expected = golden_descriptor();
            header[offset] = replacement;
            refresh_checksums(&mut header, &mut expected);
            assert_eq!(
                complete(&header, &expected),
                Err(H80Error::Corrupt),
                "{name}"
            );
        }
    }

    #[test]
    fn checksum_repaired_invalid_identity_ranges_still_refuse() {
        let mut cases: Vec<(&str, [u8; 80], H80Descriptor<'_>)> = Vec::new();

        let mut header = golden_h80();
        header[12..28].fill(0);
        let mut expected = golden_descriptor();
        expected.database_id.fill(0);
        cases.push(("zero database", header, expected));

        let mut header = golden_h80();
        header[28..44].fill(0);
        let mut expected = golden_descriptor();
        expected.writer_incarnation.fill(0);
        cases.push(("zero incarnation", header, expected));

        let mut header = golden_h80();
        header[44..52].fill(0);
        header[52..60].fill(0);
        let mut expected = golden_descriptor();
        expected.wal_id = 0;
        expected.creation_nonce[..8].fill(0);
        expected.relative_path = "wal/00000000000000000000.wal";
        cases.push(("zero id", header, expected));

        let mut header = golden_h80();
        header[44..52].fill(0xff);
        header[52..60].fill(0xff);
        let mut expected = golden_descriptor();
        expected.wal_id = u64::MAX;
        expected.creation_nonce[..8].fill(0xff);
        expected.relative_path = "wal/18446744073709551615.wal";
        cases.push(("reserved maximum id", header, expected));

        let mut header = golden_h80();
        header[52] = 2;
        let mut expected = golden_descriptor();
        expected.creation_nonce[0] = 2;
        cases.push(("nonce id prefix", header, expected));

        for (name, mut header, mut expected) in cases {
            refresh_checksums(&mut header, &mut expected);
            assert_eq!(
                complete(&header, &expected),
                Err(H80Error::Corrupt),
                "{name}"
            );
        }
    }

    #[test]
    fn exact_descriptor_and_canonical_path_are_required() {
        let header = golden_h80();
        let mut cases = Vec::new();
        let mut expected = golden_descriptor();
        expected.database_id[0] ^= 1;
        cases.push(("database swap", expected));
        let mut expected = golden_descriptor();
        expected.writer_incarnation[0] ^= 1;
        cases.push(("incarnation swap", expected));
        let mut expected = golden_descriptor();
        expected.wal_id = 2;
        cases.push(("id swap", expected));
        let mut expected = golden_descriptor();
        expected.creation_nonce[8] ^= 1;
        cases.push(("random nonce swap", expected));
        let mut expected = golden_descriptor();
        expected.start_after_sequence = 1;
        cases.push(("start-after swap", expected));
        let mut expected = golden_descriptor();
        expected.header_digest[0] ^= 1;
        cases.push(("digest swap", expected));
        for (name, expected) in cases {
            assert_eq!(
                complete(&header, &expected),
                Err(H80Error::Corrupt),
                "{name}"
            );
        }
        for path in [
            "wal/1.wal",
            "wal/0000000000000000001.wal",
            "wal/00000000000000000001.WAL",
            "WAL/00000000000000000001.wal",
            "wal/+00000000000000000001.wal",
            "wal/../wal/00000000000000000001.wal",
            "wal/00000000000000000001.wal/.",
        ] {
            let mut expected = golden_descriptor();
            expected.relative_path = path;
            assert_eq!(
                complete(&header, &expected),
                Err(H80Error::Corrupt),
                "{path}"
            );
            assert_eq!(
                pending(None, &expected),
                Err(H80Error::Corrupt),
                "absent pending path {path}"
            );
        }
    }

    #[test]
    fn absent_pending_path_still_validates_the_descriptor() {
        let mut cases = Vec::new();
        let mut expected = golden_descriptor();
        expected.database_id.fill(0);
        cases.push(("zero database", expected));
        let mut expected = golden_descriptor();
        expected.writer_incarnation.fill(0);
        cases.push(("zero incarnation", expected));
        let mut expected = golden_descriptor();
        expected.wal_id = 0;
        cases.push(("zero id", expected));
        let mut expected = golden_descriptor();
        expected.wal_id = u64::MAX;
        cases.push(("reserved maximum id", expected));
        let mut expected = golden_descriptor();
        expected.creation_nonce[0] ^= 1;
        cases.push(("nonce id mismatch", expected));
        let mut expected = golden_descriptor();
        expected.header_digest[0] ^= 1;
        cases.push(("header digest mismatch", expected));

        for (name, expected) in cases {
            assert_eq!(
                pending(None, &expected),
                Err(H80Error::Corrupt),
                "absent pending path with {name}"
            );
        }
    }

    #[test]
    fn crc_ieee_and_wrong_digest_domain_are_not_v5_integrity() {
        let mut header = golden_h80();
        let mut expected = golden_descriptor();
        let ieee_crc = crate::io::crc32c(&header[..76]);
        header[76..80].copy_from_slice(&ieee_crc.to_le_bytes());
        expected.header_digest = digest_reference(&header);
        assert_eq!(
            complete(&header, &expected),
            Err(H80Error::Corrupt),
            "IEEE substitution"
        );

        let header = golden_h80();
        let mut expected = golden_descriptor();
        expected.header_digest = *blake3::hash(&header).as_bytes();
        assert_eq!(
            complete(&header, &expected),
            Err(H80Error::Corrupt),
            "missing digest domain"
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"praxor/wal-header/v4\0");
        hasher.update(&header);
        expected.header_digest = *hasher.finalize().as_bytes();
        assert_eq!(
            complete(&header, &expected),
            Err(H80Error::Corrupt),
            "wrong digest domain"
        );
    }

    #[test]
    fn highest_nonreserved_id_uses_exact_twenty_digit_path() {
        let mut header = golden_h80();
        let mut expected = golden_descriptor();
        let id = u64::MAX - 1;
        header[44..52].copy_from_slice(&id.to_le_bytes());
        header[52..60].copy_from_slice(&id.to_le_bytes());
        expected.wal_id = id;
        expected.creation_nonce[..8].copy_from_slice(&id.to_le_bytes());
        expected.relative_path = "wal/18446744073709551614.wal";
        refresh_checksums(&mut header, &mut expected);
        assert_eq!(
            complete(&header, &expected),
            Ok(UntrustedH80 {
                database_id: expected.database_id,
                writer_incarnation: expected.writer_incarnation,
                wal_id: id,
                creation_nonce: expected.creation_nonce,
                start_after_sequence: 0,
                header_digest: expected.header_digest,
            })
        );
    }
}
