//! Bounded, chunk-fed semantics for variable protected record rows.

use crate::errors::{PraxisError, Result};
use crate::wal::record::MAX_WAL_PAYLOAD_BYTES;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariableKind {
    Descriptor,
    Payload,
}

impl VariableKind {
    pub(crate) fn minimum_len(self) -> u64 {
        match self {
            Self::Descriptor => 33,
            Self::Payload => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariableSummary {
    Descriptor {
        name_len: u32,
        namespace_len: u32,
    },
    Payload {
        user_len: u32,
        user_digest: blake3::Hash,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Step {
    Prefix,
    NameLen,
    Name,
    NamespaceLen,
    Namespace,
    Config,
    Body,
    Done,
}

pub(crate) struct VariableRowStream {
    kind: VariableKind,
    declared_len: u64,
    consumed: u64,
    step: Step,
    fixed: [u8; 20],
    fixed_used: usize,
    field_remaining: u64,
    name_len: u32,
    namespace_len: u32,
    user_len: u32,
    utf8_pending: [u8; 3],
    utf8_pending_len: usize,
    user_digest: blake3::Hasher,
}

fn corrupt(path: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

impl VariableRowStream {
    pub(crate) fn new(kind: VariableKind, declared_len: u64, path: &Path) -> Result<Self> {
        if declared_len < kind.minimum_len() || declared_len > MAX_WAL_PAYLOAD_BYTES as u64 {
            return Err(corrupt(
                path,
                "external variable record length exceeds wire bound",
            ));
        }
        Ok(Self {
            kind,
            declared_len,
            consumed: 0,
            step: Step::Prefix,
            fixed: [0; 20],
            fixed_used: 0,
            field_remaining: 0,
            name_len: 0,
            namespace_len: 0,
            user_len: 0,
            utf8_pending: [0; 3],
            utf8_pending_len: 0,
            user_digest: blake3::Hasher::new(),
        })
    }

    fn take_fixed(&mut self, input: &mut &[u8], target: usize) -> bool {
        let take = (target - self.fixed_used).min(input.len());
        self.fixed[self.fixed_used..self.fixed_used + take].copy_from_slice(&input[..take]);
        self.fixed_used += take;
        self.consumed += take as u64;
        *input = &input[take..];
        if self.fixed_used == target {
            self.fixed_used = 0;
            true
        } else {
            false
        }
    }

    fn feed_text(&mut self, bytes: &[u8], path: &Path) -> Result<()> {
        let mut input = bytes;
        if self.utf8_pending_len != 0 {
            let expected = match self.utf8_pending[0] {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => return Err(corrupt(path, "external Descriptor text is invalid UTF-8")),
            };
            let mut scalar = [0_u8; 4];
            scalar[..self.utf8_pending_len]
                .copy_from_slice(&self.utf8_pending[..self.utf8_pending_len]);
            let take = (expected - self.utf8_pending_len).min(input.len());
            scalar[self.utf8_pending_len..self.utf8_pending_len + take]
                .copy_from_slice(&input[..take]);
            self.utf8_pending_len += take;
            input = &input[take..];
            if self.utf8_pending_len != expected {
                self.utf8_pending[..self.utf8_pending_len]
                    .copy_from_slice(&scalar[..self.utf8_pending_len]);
                return Ok(());
            }
            std::str::from_utf8(&scalar[..expected])
                .map_err(|_| corrupt(path, "external Descriptor text is invalid UTF-8"))?;
            self.utf8_pending_len = 0;
        }
        match std::str::from_utf8(input) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() => {
                let tail = &input[error.valid_up_to()..];
                if tail.is_empty() || tail.len() > self.utf8_pending.len() {
                    return Err(corrupt(path, "external Descriptor text is invalid UTF-8"));
                }
                self.utf8_pending[..tail.len()].copy_from_slice(tail);
                self.utf8_pending_len = tail.len();
                Ok(())
            }
            Err(_) => Err(corrupt(path, "external Descriptor text is invalid UTF-8")),
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8], path: &Path) -> Result<()> {
        if self
            .consumed
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.declared_len)
        {
            return Err(corrupt(
                path,
                "external variable record exceeds declared length",
            ));
        }
        let mut input = bytes;
        while !input.is_empty() {
            match self.step {
                Step::Prefix => {
                    let target = if self.kind == VariableKind::Descriptor {
                        20
                    } else {
                        12
                    };
                    if !self.take_fixed(&mut input, target) {
                        continue;
                    }
                    if self.kind == VariableKind::Descriptor {
                        if &self.fixed[..4] != b"PRD1"
                            || self.fixed[4..8] != [1, 0, 0, 0]
                            || self.fixed[8..12] != [1, 1, 1, 0]
                            || u64::from_le_bytes(self.fixed[12..20].try_into().unwrap()) != 1
                        {
                            return Err(corrupt(
                                path,
                                "external Descriptor fixed fields are invalid",
                            ));
                        }
                        self.step = Step::NameLen;
                    } else {
                        if &self.fixed[..4] != b"PRP1" || self.fixed[4..8] != [1, 0, 0, 0] {
                            return Err(corrupt(path, "external Payload fixed fields are invalid"));
                        }
                        self.user_len = u32::from_le_bytes(self.fixed[8..12].try_into().unwrap());
                        if self.user_len as u64 != self.declared_len - 12 {
                            return Err(corrupt(path, "external Payload inner length disagrees"));
                        }
                        self.field_remaining = self.user_len as u64;
                        self.step = if self.field_remaining == 0 {
                            Step::Done
                        } else {
                            Step::Body
                        };
                    }
                }
                Step::NameLen => {
                    if !self.take_fixed(&mut input, 4) {
                        continue;
                    }
                    self.name_len = u32::from_le_bytes(self.fixed[..4].try_into().unwrap());
                    if self.name_len == 0
                        || self
                            .consumed
                            .checked_add(self.name_len as u64 + 8)
                            .is_none_or(|end| end > self.declared_len)
                    {
                        return Err(corrupt(path, "external Descriptor name length is invalid"));
                    }
                    self.field_remaining = self.name_len as u64;
                    self.step = Step::Name;
                }
                Step::Name | Step::Namespace => {
                    let take = self.field_remaining.min(input.len() as u64) as usize;
                    self.feed_text(&input[..take], path)?;
                    self.consumed += take as u64;
                    self.field_remaining -= take as u64;
                    input = &input[take..];
                    if self.field_remaining == 0 {
                        if self.utf8_pending_len != 0 {
                            return Err(corrupt(
                                path,
                                "external Descriptor text ends in truncated UTF-8",
                            ));
                        }
                        self.step = if self.step == Step::Name {
                            Step::NamespaceLen
                        } else {
                            Step::Config
                        };
                    }
                }
                Step::NamespaceLen => {
                    if !self.take_fixed(&mut input, 4) {
                        continue;
                    }
                    self.namespace_len = u32::from_le_bytes(self.fixed[..4].try_into().unwrap());
                    if self
                        .consumed
                        .checked_add(self.namespace_len as u64 + 4)
                        .is_none_or(|end| end > self.declared_len)
                    {
                        return Err(corrupt(
                            path,
                            "external Descriptor namespace length is invalid",
                        ));
                    }
                    self.field_remaining = self.namespace_len as u64;
                    self.step = if self.field_remaining == 0 {
                        Step::Config
                    } else {
                        Step::Namespace
                    };
                }
                Step::Config => {
                    if !self.take_fixed(&mut input, 4) {
                        continue;
                    }
                    if self.fixed[..4] != [0; 4] {
                        return Err(corrupt(
                            path,
                            "external Descriptor configuration is invalid",
                        ));
                    }
                    self.step = Step::Done;
                }
                Step::Body => {
                    let take = self.field_remaining.min(input.len() as u64) as usize;
                    self.user_digest.update(&input[..take]);
                    self.consumed += take as u64;
                    self.field_remaining -= take as u64;
                    input = &input[take..];
                    if self.field_remaining == 0 {
                        self.step = Step::Done;
                    }
                }
                Step::Done => {
                    return Err(corrupt(path, "external variable record has trailing bytes"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self, path: &Path) -> Result<VariableSummary> {
        if self.consumed != self.declared_len || self.step != Step::Done {
            return Err(corrupt(path, "external variable record is truncated"));
        }
        Ok(match self.kind {
            VariableKind::Descriptor => VariableSummary::Descriptor {
                name_len: self.name_len,
                namespace_len: self.namespace_len,
            },
            VariableKind::Payload => VariableSummary::Payload {
                user_len: self.user_len,
                user_digest: self.user_digest.finalize(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_records::codec::{Key, Row};

    fn streamed(kind: VariableKind, bytes: &[u8], chunk: usize) -> Result<VariableSummary> {
        let path = Path::new("variable-stream-test");
        let mut parser = VariableRowStream::new(kind, bytes.len() as u64, path)?;
        for part in bytes.chunks(chunk) {
            parser.feed(part, path)?;
        }
        parser.finish(path)
    }

    #[test]
    fn descriptor_parses_every_fixed_field_split_and_empty_namespace() {
        let bytes = Row::Descriptor {
            name: "idx",
            namespace: "",
        }
        .encode()
        .unwrap();
        assert_eq!(bytes.len(), 35);
        for chunk in 1..=bytes.len() {
            assert_eq!(
                streamed(VariableKind::Descriptor, &bytes, chunk).unwrap(),
                VariableSummary::Descriptor {
                    name_len: 3,
                    namespace_len: 0
                }
            );
        }
        assert!(Row::decode(&Key::Descriptor(1), &bytes, Path::new("test")).is_ok());
    }

    #[test]
    fn payload_parses_every_prefix_split_and_hashes_only_user_bytes() {
        let bytes = Row::Payload(b"abc").encode().unwrap();
        assert_eq!(bytes.len(), 15);
        for chunk in 1..=bytes.len() {
            assert_eq!(
                streamed(VariableKind::Payload, &bytes, chunk).unwrap(),
                VariableSummary::Payload {
                    user_len: 3,
                    user_digest: blake3::hash(b"abc")
                }
            );
        }
        let empty = Row::Payload(b"").encode().unwrap();
        assert_eq!(
            streamed(VariableKind::Payload, &empty, 1).unwrap(),
            VariableSummary::Payload {
                user_len: 0,
                user_digest: blake3::hash(b"")
            }
        );
    }

    #[test]
    fn descriptor_accepts_split_multibyte_scalar_at_scan_boundary() {
        let mut namespace = "x".repeat(65_504);
        namespace.push('é');
        namespace.push('😀');
        let bytes = Row::Descriptor {
            name: "idx",
            namespace: &namespace,
        }
        .encode()
        .unwrap();
        assert_eq!(bytes[65_535], 0xC3);
        assert_eq!(bytes[65_536], 0xA9);
        assert_eq!(
            streamed(VariableKind::Descriptor, &bytes, 65_536).unwrap(),
            VariableSummary::Descriptor {
                name_len: 3,
                namespace_len: 65_510
            }
        );
        assert_eq!(
            streamed(VariableKind::Descriptor, &bytes, 1).unwrap(),
            VariableSummary::Descriptor {
                name_len: 3,
                namespace_len: 65_510
            }
        );
    }

    #[test]
    fn descriptor_rejects_invalid_lengths_utf8_and_configuration() {
        let valid = Row::Descriptor {
            name: "idx",
            namespace: "n",
        }
        .encode()
        .unwrap();
        let mut wrong_name = valid.clone();
        wrong_name[20..24].copy_from_slice(&0_u32.to_le_bytes());
        let mut forged_name = valid.clone();
        forged_name[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut truncated_utf8 = valid.clone();
        truncated_utf8[24] = 0xC3;
        let mut wrong_namespace = valid.clone();
        wrong_namespace[27..31].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut invalid_config = valid.clone();
        *invalid_config.last_mut().unwrap() = 1;
        let mut trailing = valid.clone();
        trailing.push(0);
        for bytes in [
            wrong_name,
            forged_name,
            truncated_utf8,
            wrong_namespace,
            invalid_config,
            trailing,
        ] {
            assert!(streamed(VariableKind::Descriptor, &bytes, 1).is_err());
            assert!(Row::decode(&Key::Descriptor(1), &bytes, Path::new("test")).is_err());
        }
    }

    #[test]
    fn descriptor_rejects_wrong_magic_schema_flags_mapping_and_field_boundary_utf8() {
        let valid = Row::Descriptor {
            name: "a",
            namespace: "",
        }
        .encode()
        .unwrap();
        assert_eq!(valid.len(), 33);
        let mut variants = Vec::new();
        for (index, byte) in [(0, b'X'), (4, 2), (6, 1), (8, 2), (12, 2), (24, 0xC3)] {
            let mut broken = valid.clone();
            broken[index] = byte;
            variants.push(broken);
        }
        for bytes in variants {
            assert!(streamed(VariableKind::Descriptor, &bytes, 7).is_err());
            assert!(Row::decode(&Key::Descriptor(1), &bytes, Path::new("test")).is_err());
        }
    }

    #[test]
    fn payload_rejects_inner_length_and_trailing_bytes() {
        let valid = Row::Payload(b"abc").encode().unwrap();
        let mut wrong = valid.clone();
        wrong[8..12].copy_from_slice(&4_u32.to_le_bytes());
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut wrong_magic = valid.clone();
        wrong_magic[0] = b'X';
        let mut wrong_schema = valid.clone();
        wrong_schema[4] = 2;
        let mut wrong_flags = valid.clone();
        wrong_flags[6] = 1;
        for bytes in [wrong, trailing, wrong_magic, wrong_schema, wrong_flags] {
            assert!(streamed(VariableKind::Payload, &bytes, 1).is_err());
            assert!(Row::decode(&Key::Payload(1), &bytes, Path::new("test")).is_err());
        }
    }

    #[test]
    fn parser_rejects_feed_past_declared_length() {
        let bytes = Row::Payload(b"abc").encode().unwrap();
        let path = Path::new("test");
        let mut parser =
            VariableRowStream::new(VariableKind::Payload, bytes.len() as u64, path).unwrap();
        parser.feed(&bytes, path).unwrap();
        assert!(parser.feed(b"x", path).is_err());
    }
}
