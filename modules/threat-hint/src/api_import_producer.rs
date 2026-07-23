//! Local-only `api_import` production from exact Linux ELF artifact bytes.

use core::str;

use object::{BinaryFormat, Object, ObjectSymbol};
use thiserror::Error;

use crate::observable_bundle::validate_api_import;
use crate::{ObservableBundle, ScopeFormat, ScopePlatform};

/// Maximum ELF artifact size accepted by the bounded local parser.
pub const MAX_ELF_API_IMPORT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of dynamic symbols inspected per artifact.
pub const MAX_ELF_DYNAMIC_SYMBOLS: usize = 4096;

/// Fail-closed errors returned by the local ELF import producer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ElfApiImportProducerError {
    /// The artifact is empty, malformed, or not a supported ELF object.
    #[error("invalid ELF artifact")]
    InvalidArtifact,
    /// The artifact exceeds the bounded parser input size.
    #[error("ELF artifact exceeds local parser size limit")]
    ArtifactTooLarge,
    /// At least one extracted import cannot be represented by the closed grammar.
    #[error("ELF artifact contains an unsupported import")]
    UnsupportedImport,
    /// The artifact contains no representable dynamic imports.
    #[error("ELF artifact contains no supported imports")]
    NoImports,
    /// The dynamic import table exceeds the local processing budget.
    #[error("ELF artifact exceeds local import limit")]
    TooManyDynamicSymbols,
    /// The selected index is outside the sorted unique import set.
    #[error("invalid ELF import selection")]
    InvalidSelection,
    /// The internally derived observable could not be canonicalized.
    #[error("failed to canonicalize ELF import")]
    Canonicalization,
}

/// Produces one review-required `api_import` from exact Linux ELF bytes.
///
/// Imports are read from the ELF dynamic import table, validated without
/// normalization, sorted by exact ASCII byte order, and deduplicated before
/// `import_index` selects one entry. The function performs no filesystem,
/// transport, analysis, proof, wallet, or chain operation.
pub fn produce_elf_api_import_bundle(
    artifact_bytes: &[u8],
    import_index: usize,
) -> Result<ObservableBundle, ElfApiImportProducerError> {
    if artifact_bytes.is_empty() {
        return Err(ElfApiImportProducerError::InvalidArtifact);
    }
    if artifact_bytes.len() > MAX_ELF_API_IMPORT_ARTIFACT_BYTES {
        return Err(ElfApiImportProducerError::ArtifactTooLarge);
    }

    let artifact = object::File::parse(artifact_bytes)
        .map_err(|_| ElfApiImportProducerError::InvalidArtifact)?;
    if artifact.format() != BinaryFormat::Elf {
        return Err(ElfApiImportProducerError::InvalidArtifact);
    }

    let mut names = Vec::new();
    for (symbol_index, symbol) in artifact.dynamic_symbols().enumerate() {
        if symbol_index == MAX_ELF_DYNAMIC_SYMBOLS {
            return Err(ElfApiImportProducerError::TooManyDynamicSymbols);
        }
        if !symbol.is_undefined() {
            continue;
        }
        let name_bytes = symbol
            .name_bytes()
            .map_err(|_| ElfApiImportProducerError::InvalidArtifact)?;
        if name_bytes.is_empty() {
            continue;
        }
        let name =
            str::from_utf8(name_bytes).map_err(|_| ElfApiImportProducerError::UnsupportedImport)?;
        validate_api_import(name).map_err(|_| ElfApiImportProducerError::UnsupportedImport)?;
        names.push(name);
    }
    names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    names.dedup();

    if names.is_empty() {
        return Err(ElfApiImportProducerError::NoImports);
    }
    let selected = names
        .get(import_index)
        .ok_or(ElfApiImportProducerError::InvalidSelection)?;

    ObservableBundle::from_review_required_api_import(
        ScopePlatform::Linux,
        ScopeFormat::Elf,
        selected,
    )
    .map_err(|_| ElfApiImportProducerError::Canonicalization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisclosurePolicy, ObservableKind};

    const ELF_HEADER_BYTES: usize = 64;
    const ELF64_SYMBOL_BYTES: usize = 24;
    const ELF64_SECTION_HEADER_BYTES: usize = 64;

    fn align(value: usize, alignment: usize) -> usize {
        (value + alignment - 1) & !(alignment - 1)
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn write_section_header(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        section_type: u32,
        section_offset: usize,
        section_size: usize,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: u64,
    ) {
        write_u32(bytes, offset, name);
        write_u32(bytes, offset + 4, section_type);
        write_u64(
            bytes,
            offset + 24,
            u64::try_from(section_offset).expect("test section offset"),
        );
        write_u64(
            bytes,
            offset + 32,
            u64::try_from(section_size).expect("test section size"),
        );
        write_u32(bytes, offset + 40, link);
        write_u32(bytes, offset + 44, info);
        write_u64(bytes, offset + 48, alignment);
        write_u64(bytes, offset + 56, entry_size);
    }

    fn elf_fixture(imports: &[&[u8]]) -> Vec<u8> {
        let mut dynamic_strings = vec![0];
        let mut name_offsets = Vec::with_capacity(imports.len());
        for import in imports {
            name_offsets
                .push(u32::try_from(dynamic_strings.len()).expect("test dynamic string offset"));
            dynamic_strings.extend_from_slice(import);
            dynamic_strings.push(0);
        }

        let mut dynamic_symbols = vec![0; ELF64_SYMBOL_BYTES];
        for name_offset in name_offsets {
            let entry_offset = dynamic_symbols.len();
            dynamic_symbols.resize(entry_offset + ELF64_SYMBOL_BYTES, 0);
            write_u32(&mut dynamic_symbols, entry_offset, name_offset);
            dynamic_symbols[entry_offset + 4] = 0x12;
        }

        let section_names = b"\0.dynstr\0.dynsym\0.shstrtab\0";
        let dynamic_strings_offset = ELF_HEADER_BYTES;
        let dynamic_symbols_offset = align(dynamic_strings_offset + dynamic_strings.len(), 8);
        let section_names_offset = dynamic_symbols_offset + dynamic_symbols.len();
        let section_headers_offset = align(section_names_offset + section_names.len(), 8);
        let mut bytes = vec![0; section_headers_offset + 4 * ELF64_SECTION_HEADER_BYTES];

        bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_u16(&mut bytes, 16, 3);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(
            &mut bytes,
            40,
            u64::try_from(section_headers_offset).expect("test section headers offset"),
        );
        write_u16(&mut bytes, 52, ELF_HEADER_BYTES as u16);
        write_u16(&mut bytes, 54, 56);
        write_u16(&mut bytes, 58, ELF64_SECTION_HEADER_BYTES as u16);
        write_u16(&mut bytes, 60, 4);
        write_u16(&mut bytes, 62, 3);

        bytes[dynamic_strings_offset..dynamic_strings_offset + dynamic_strings.len()]
            .copy_from_slice(&dynamic_strings);
        bytes[dynamic_symbols_offset..dynamic_symbols_offset + dynamic_symbols.len()]
            .copy_from_slice(&dynamic_symbols);
        bytes[section_names_offset..section_names_offset + section_names.len()]
            .copy_from_slice(section_names);

        write_section_header(
            &mut bytes,
            section_headers_offset + ELF64_SECTION_HEADER_BYTES,
            1,
            3,
            dynamic_strings_offset,
            dynamic_strings.len(),
            0,
            0,
            1,
            0,
        );
        write_section_header(
            &mut bytes,
            section_headers_offset + 2 * ELF64_SECTION_HEADER_BYTES,
            9,
            11,
            dynamic_symbols_offset,
            dynamic_symbols.len(),
            1,
            1,
            8,
            ELF64_SYMBOL_BYTES as u64,
        );
        write_section_header(
            &mut bytes,
            section_headers_offset + 3 * ELF64_SECTION_HEADER_BYTES,
            17,
            3,
            section_names_offset,
            section_names.len(),
            0,
            0,
            1,
            0,
        );

        bytes
    }

    #[test]
    fn sorted_unique_import_index_produces_review_required_bundle() {
        let artifact = elf_fixture(&[b"mmap", b"close", b"mmap", b"pthread_create"]);
        let expected = ["close", "mmap", "pthread_create"];

        for (index, expected_import) in expected.into_iter().enumerate() {
            let bundle = produce_elf_api_import_bundle(&artifact, index).expect("valid ELF import");
            assert_eq!(
                bundle.disclosure_policy(),
                DisclosurePolicy::ReviewRequiredV1
            );
            assert_eq!(bundle.scope().platform(), ScopePlatform::Linux);
            assert_eq!(bundle.scope().format(), ScopeFormat::Elf);
            assert_eq!(bundle.observables().len(), 1);
            assert_eq!(bundle.observables()[0].kind(), ObservableKind::ApiImport);
            assert_eq!(bundle.observables()[0].value(), expected_import);
        }
    }

    #[test]
    fn invalid_artifacts_and_selection_fail_closed() {
        assert!(matches!(
            produce_elf_api_import_bundle(&[], 0),
            Err(ElfApiImportProducerError::InvalidArtifact)
        ));
        assert!(matches!(
            produce_elf_api_import_bundle(b"not an ELF", 0),
            Err(ElfApiImportProducerError::InvalidArtifact)
        ));
        assert!(matches!(
            produce_elf_api_import_bundle(&elf_fixture(&[]), 0),
            Err(ElfApiImportProducerError::NoImports)
        ));
        assert!(matches!(
            produce_elf_api_import_bundle(&elf_fixture(&[b"mmap"]), 1),
            Err(ElfApiImportProducerError::InvalidSelection)
        ));
    }

    #[test]
    fn one_unsupported_import_rejects_the_complete_artifact() {
        let error = match produce_elf_api_import_bundle(&elf_fixture(&[b"mmap", b"bad$name"]), 0) {
            Err(error) => error,
            Ok(_) => panic!("unsupported import must fail closed"),
        };
        assert_eq!(error, ElfApiImportProducerError::UnsupportedImport);
        assert!(!error.to_string().contains("bad$name"));
    }

    #[test]
    fn oversized_input_rejects_before_parsing() {
        let artifact = vec![0; MAX_ELF_API_IMPORT_ARTIFACT_BYTES + 1];
        assert!(matches!(
            produce_elf_api_import_bundle(&artifact, 0),
            Err(ElfApiImportProducerError::ArtifactTooLarge)
        ));
    }

    #[test]
    fn import_count_budget_rejects_before_sorting() {
        let imports = vec![b"mmap".as_slice(); MAX_ELF_DYNAMIC_SYMBOLS + 1];
        assert!(matches!(
            produce_elf_api_import_bundle(&elf_fixture(&imports), 0),
            Err(ElfApiImportProducerError::TooManyDynamicSymbols)
        ));
    }
}
