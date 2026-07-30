//! Local-only `api_import` production from exact Windows PE artifact bytes.

use core::str;

use object::read::pe::{ImageNtHeaders, ImageThunkData, PeFile};
use object::{BinaryFormat, LittleEndian as LE};
use thiserror::Error;

use crate::observable_bundle::validate_api_import;
use crate::{ObservableBundle, ScopeFormat, ScopePlatform};

/// Maximum PE artifact size accepted by the bounded local parser.
pub const MAX_PE_API_IMPORT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of import entries inspected per artifact.
pub const MAX_PE_IMPORTS: usize = 4096;

/// Fail-closed errors returned by the local PE import producer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeApiImportProducerError {
    /// The artifact is empty, malformed, or not a supported PE object.
    #[error("invalid PE artifact")]
    InvalidArtifact,
    /// The artifact exceeds the bounded parser input size.
    #[error("PE artifact exceeds local parser size limit")]
    ArtifactTooLarge,
    /// At least one extracted import cannot be represented by the closed grammar.
    #[error("PE artifact contains an unsupported import")]
    UnsupportedImport,
    /// The artifact contains no representable named imports.
    #[error("PE artifact contains no supported imports")]
    NoImports,
    /// The import table exceeds the local processing budget.
    #[error("PE artifact exceeds local import limit")]
    TooManyImports,
    /// The selected index is outside the sorted unique import set.
    #[error("invalid PE import selection")]
    InvalidSelection,
    /// The internally derived observable could not be canonicalized.
    #[error("failed to canonicalize PE import")]
    Canonicalization,
}

/// Produces one review-required `api_import` from exact Windows PE bytes.
///
/// Imports are read from the PE import table, validated without
/// normalization, sorted by exact ASCII byte order, and deduplicated before
/// `import_index` selects one entry. Ordinal-only imports are not
/// representable and reject the complete artifact; library names and ordinals
/// are never used as observable values. The function performs no filesystem,
/// transport, analysis, proof, wallet, or chain operation.
pub fn produce_pe_api_import_bundle(
    artifact_bytes: &[u8],
    import_index: usize,
) -> Result<ObservableBundle, PeApiImportProducerError> {
    if artifact_bytes.is_empty() {
        return Err(PeApiImportProducerError::InvalidArtifact);
    }
    if artifact_bytes.len() > MAX_PE_API_IMPORT_ARTIFACT_BYTES {
        return Err(PeApiImportProducerError::ArtifactTooLarge);
    }

    let artifact = object::File::parse(artifact_bytes)
        .map_err(|_| PeApiImportProducerError::InvalidArtifact)?;
    if artifact.format() != BinaryFormat::Pe {
        return Err(PeApiImportProducerError::InvalidArtifact);
    }

    let mut names = match &artifact {
        object::File::Pe32(file) => extract_named_imports(file)?,
        object::File::Pe64(file) => extract_named_imports(file)?,
        _ => return Err(PeApiImportProducerError::InvalidArtifact),
    };
    names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    names.dedup();

    if names.is_empty() {
        return Err(PeApiImportProducerError::NoImports);
    }
    let selected = names
        .get(import_index)
        .ok_or(PeApiImportProducerError::InvalidSelection)?;

    ObservableBundle::from_review_required_api_import(
        ScopePlatform::Windows,
        ScopeFormat::Pe,
        selected,
    )
    .map_err(|_| PeApiImportProducerError::Canonicalization)
}

fn extract_named_imports<'data, Pe: ImageNtHeaders>(
    file: &PeFile<'data, Pe>,
) -> Result<Vec<&'data str>, PeApiImportProducerError> {
    let Some(import_table) = file
        .import_table()
        .map_err(|_| PeApiImportProducerError::InvalidArtifact)?
    else {
        return Ok(Vec::new());
    };

    let mut names = Vec::new();
    let mut processed = 0usize;
    let mut descriptors = import_table
        .descriptors()
        .map_err(|_| PeApiImportProducerError::InvalidArtifact)?;
    while let Some(descriptor) = descriptors
        .next()
        .map_err(|_| PeApiImportProducerError::InvalidArtifact)?
    {
        let library_name = import_table
            .name(descriptor.name.get(LE))
            .map_err(|_| PeApiImportProducerError::InvalidArtifact)?;
        if library_name.is_empty() {
            return Err(PeApiImportProducerError::InvalidArtifact);
        }

        let mut first_thunk = descriptor.original_first_thunk.get(LE);
        if first_thunk == 0 {
            if descriptor.time_date_stamp.get(LE) != 0 {
                return Err(PeApiImportProducerError::InvalidArtifact);
            }
            first_thunk = descriptor.first_thunk.get(LE);
        }
        if first_thunk == 0 {
            return Err(PeApiImportProducerError::InvalidArtifact);
        }
        let mut thunks = import_table
            .thunks(first_thunk)
            .map_err(|_| PeApiImportProducerError::InvalidArtifact)?;
        while let Some(thunk) = thunks
            .next::<Pe>()
            .map_err(|_| PeApiImportProducerError::InvalidArtifact)?
        {
            if processed == MAX_PE_IMPORTS {
                return Err(PeApiImportProducerError::TooManyImports);
            }
            processed += 1;
            if thunk.is_ordinal() {
                return Err(PeApiImportProducerError::UnsupportedImport);
            }
            let (_hint, name_bytes) = import_table
                .hint_name(thunk.address())
                .map_err(|_| PeApiImportProducerError::InvalidArtifact)?;
            let name = str::from_utf8(name_bytes)
                .map_err(|_| PeApiImportProducerError::UnsupportedImport)?;
            validate_api_import(name).map_err(|_| PeApiImportProducerError::UnsupportedImport)?;
            names.push(name);
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisclosurePolicy, ObservableKind};

    const DOS_HEADER_BYTES: usize = 64;
    const COFF_HEADER_BYTES: usize = 20;
    const PE32_OPTIONAL_HEADER_BYTES: usize = 224;
    const PE32_PLUS_OPTIONAL_HEADER_BYTES: usize = 240;
    const SECTION_HEADER_BYTES: usize = 40;
    const SECTION_DATA_OFFSET: usize = 512;
    const SECTION_RVA: u32 = 0x1000;
    const IMPORT_DESCRIPTOR_BYTES: usize = 20;
    const PE32_THUNK_BYTES: usize = 4;
    const PE32_PLUS_THUNK_BYTES: usize = 8;

    #[derive(Clone, Copy)]
    enum TestPeKind {
        Pe32,
        Pe32Plus,
    }

    enum TestThunk<'a> {
        Name(&'a [u8]),
        Ordinal(u16),
    }

    struct TestImportLibrary<'a> {
        name: &'a [u8],
        thunks: &'a [TestThunk<'a>],
    }

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

    fn pe_fixture(kind: TestPeKind, thunks: &[TestThunk<'_>]) -> Vec<u8> {
        let library_name = b"KERNEL32.dll\0";
        let thunk_bytes = match kind {
            TestPeKind::Pe32 => PE32_THUNK_BYTES,
            TestPeKind::Pe32Plus => PE32_PLUS_THUNK_BYTES,
        };
        let ilt_offset = 2 * IMPORT_DESCRIPTOR_BYTES;
        let hint_names_offset = align(ilt_offset + (thunks.len() + 1) * thunk_bytes, 2);

        let mut section = vec![0; hint_names_offset];
        let mut hint_name_rvas = Vec::with_capacity(thunks.len());
        for thunk in thunks {
            if let TestThunk::Name(name) = thunk {
                hint_name_rvas
                    .push(u32::try_from(SECTION_RVA as usize + section.len()).expect("test RVA"));
                section.extend_from_slice(&0u16.to_le_bytes());
                section.extend_from_slice(name);
                section.push(0);
                section.resize(align(section.len(), 2), 0);
            } else {
                hint_name_rvas.push(0);
            }
        }
        let library_name_rva =
            u32::try_from(SECTION_RVA as usize + section.len()).expect("test library name RVA");
        section.extend_from_slice(library_name);

        let ilt_rva = SECTION_RVA + u32::try_from(ilt_offset).expect("test ILT RVA");
        write_u32(&mut section, 0, ilt_rva);
        write_u32(&mut section, 12, library_name_rva);
        write_u32(&mut section, 16, ilt_rva);
        for (index, thunk) in thunks.iter().enumerate() {
            let value = match thunk {
                TestThunk::Name(_) => u64::from(hint_name_rvas[index]),
                TestThunk::Ordinal(ordinal) => {
                    let ordinal_flag = match kind {
                        TestPeKind::Pe32 => 1u64 << 31,
                        TestPeKind::Pe32Plus => 1u64 << 63,
                    };
                    ordinal_flag | u64::from(*ordinal)
                }
            };
            let offset = ilt_offset + index * thunk_bytes;
            match kind {
                TestPeKind::Pe32 => write_u32(
                    &mut section,
                    offset,
                    u32::try_from(value).expect("test PE32 thunk"),
                ),
                TestPeKind::Pe32Plus => write_u64(&mut section, offset, value),
            }
        }

        let (
            machine,
            optional_header_bytes,
            optional_magic,
            number_of_rva_and_sizes_offset,
            import_directory_offset,
        ) = match kind {
            TestPeKind::Pe32 => (0x014c, PE32_OPTIONAL_HEADER_BYTES, 0x10b, 92, 104),
            TestPeKind::Pe32Plus => (0x8664, PE32_PLUS_OPTIONAL_HEADER_BYTES, 0x20b, 108, 120),
        };
        let headers_bytes =
            DOS_HEADER_BYTES + 4 + COFF_HEADER_BYTES + optional_header_bytes + SECTION_HEADER_BYTES;
        let mut bytes = vec![0; SECTION_DATA_OFFSET + section.len()];
        bytes[0..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, DOS_HEADER_BYTES as u32);
        bytes[DOS_HEADER_BYTES..DOS_HEADER_BYTES + 4].copy_from_slice(b"PE\0\0");

        let coff = DOS_HEADER_BYTES + 4;
        write_u16(&mut bytes, coff, machine);
        write_u16(&mut bytes, coff + 2, 1);
        write_u16(
            &mut bytes,
            coff + 16,
            u16::try_from(optional_header_bytes).expect("test optional header size"),
        );
        write_u16(&mut bytes, coff + 18, 0x2022);

        let optional = coff + COFF_HEADER_BYTES;
        write_u16(&mut bytes, optional, optional_magic);
        write_u32(&mut bytes, optional + number_of_rva_and_sizes_offset, 16);
        write_u32(&mut bytes, optional + import_directory_offset, SECTION_RVA);
        write_u32(
            &mut bytes,
            optional + import_directory_offset + 4,
            (2 * IMPORT_DESCRIPTOR_BYTES) as u32,
        );

        let section_header = optional + optional_header_bytes;
        assert_eq!(section_header + SECTION_HEADER_BYTES, headers_bytes);
        bytes[section_header..section_header + 8].copy_from_slice(b".idata\0\0");
        write_u32(
            &mut bytes,
            section_header + 8,
            u32::try_from(section.len()).expect("test virtual size"),
        );
        write_u32(&mut bytes, section_header + 12, SECTION_RVA);
        write_u32(
            &mut bytes,
            section_header + 16,
            u32::try_from(section.len()).expect("test raw size"),
        );
        write_u32(&mut bytes, section_header + 20, SECTION_DATA_OFFSET as u32);

        bytes[SECTION_DATA_OFFSET..].copy_from_slice(&section);
        bytes
    }

    fn pe32_fixture(thunks: &[TestThunk<'_>]) -> Vec<u8> {
        pe_fixture(TestPeKind::Pe32, thunks)
    }

    fn pe32_plus_fixture(thunks: &[TestThunk<'_>]) -> Vec<u8> {
        pe_fixture(TestPeKind::Pe32Plus, thunks)
    }

    fn pe32_plus_multi_library_fixture(libraries: &[TestImportLibrary<'_>]) -> Vec<u8> {
        assert!(!libraries.is_empty());
        let descriptor_bytes = (libraries.len() + 1) * IMPORT_DESCRIPTOR_BYTES;
        let mut section = vec![0; descriptor_bytes];

        for (library_index, library) in libraries.iter().enumerate() {
            assert!(!library.name.is_empty());
            assert!(!library.name.contains(&0));

            let ilt_offset = align(section.len(), PE32_PLUS_THUNK_BYTES);
            section.resize(
                ilt_offset + (library.thunks.len() + 1) * PE32_PLUS_THUNK_BYTES,
                0,
            );

            for (thunk_index, thunk) in library.thunks.iter().enumerate() {
                let value = match thunk {
                    TestThunk::Name(name) => {
                        let hint_name_rva = u32::try_from(SECTION_RVA as usize + section.len())
                            .expect("test hint/name RVA");
                        section.extend_from_slice(&0u16.to_le_bytes());
                        section.extend_from_slice(name);
                        section.push(0);
                        section.resize(align(section.len(), 2), 0);
                        u64::from(hint_name_rva)
                    }
                    TestThunk::Ordinal(ordinal) => (1u64 << 63) | u64::from(*ordinal),
                };
                write_u64(
                    &mut section,
                    ilt_offset + thunk_index * PE32_PLUS_THUNK_BYTES,
                    value,
                );
            }

            let library_name_rva =
                u32::try_from(SECTION_RVA as usize + section.len()).expect("test library name RVA");
            section.extend_from_slice(library.name);
            section.push(0);

            let ilt_rva = SECTION_RVA + u32::try_from(ilt_offset).expect("test ILT RVA");
            let descriptor_offset = library_index * IMPORT_DESCRIPTOR_BYTES;
            write_u32(&mut section, descriptor_offset, ilt_rva);
            write_u32(&mut section, descriptor_offset + 12, library_name_rva);
            write_u32(&mut section, descriptor_offset + 16, ilt_rva);
        }

        let mut bytes = pe32_plus_fixture(&[]);
        bytes.truncate(SECTION_DATA_OFFSET);
        let coff = DOS_HEADER_BYTES + 4;
        let optional = coff + COFF_HEADER_BYTES;
        let section_header = optional + PE32_PLUS_OPTIONAL_HEADER_BYTES;
        write_u32(
            &mut bytes,
            optional + 124,
            u32::try_from(descriptor_bytes).expect("test import directory size"),
        );
        write_u32(
            &mut bytes,
            section_header + 8,
            u32::try_from(section.len()).expect("test virtual size"),
        );
        write_u32(
            &mut bytes,
            section_header + 16,
            u32::try_from(section.len()).expect("test raw size"),
        );
        bytes.extend_from_slice(&section);
        bytes
    }

    fn named_fixture(names: &[&[u8]]) -> Vec<u8> {
        let thunks: Vec<TestThunk<'_>> = names.iter().map(|name| TestThunk::Name(name)).collect();
        pe32_plus_fixture(&thunks)
    }

    #[test]
    fn sorted_unique_import_index_produces_review_required_bundle() {
        let artifact = named_fixture(&[b"ReadFile", b"CreateFileW", b"VirtualAlloc", b"ReadFile"]);
        let expected = ["CreateFileW", "ReadFile", "VirtualAlloc"];

        for (index, expected_import) in expected.into_iter().enumerate() {
            let bundle = produce_pe_api_import_bundle(&artifact, index).expect("valid PE import");
            assert_eq!(
                bundle.disclosure_policy(),
                DisclosurePolicy::ReviewRequiredV1
            );
            assert_eq!(bundle.scope().platform(), ScopePlatform::Windows);
            assert_eq!(bundle.scope().format(), ScopeFormat::Pe);
            assert_eq!(bundle.observables().len(), 1);
            assert_eq!(bundle.observables()[0].kind(), ObservableKind::ApiImport);
            assert_eq!(bundle.observables()[0].value(), expected_import);
        }
    }

    #[test]
    fn invalid_artifacts_and_selection_fail_closed() {
        assert!(matches!(
            produce_pe_api_import_bundle(&[], 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));
        assert!(matches!(
            produce_pe_api_import_bundle(b"not a PE", 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));
        let mut truncated = named_fixture(&[b"ReadFile"]);
        truncated.truncate(128);
        assert!(matches!(
            produce_pe_api_import_bundle(&truncated, 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));
        assert!(matches!(
            produce_pe_api_import_bundle(&named_fixture(&[]), 0),
            Err(PeApiImportProducerError::NoImports)
        ));
        assert!(matches!(
            produce_pe_api_import_bundle(&named_fixture(&[b"ReadFile"]), 1),
            Err(PeApiImportProducerError::InvalidSelection)
        ));
    }

    #[test]
    fn one_unsupported_import_rejects_the_complete_artifact() {
        let error =
            match produce_pe_api_import_bundle(&named_fixture(&[b"ReadFile", b"bad$name"]), 0) {
                Err(error) => error,
                Ok(_) => panic!("unsupported import must fail closed"),
            };
        assert_eq!(error, PeApiImportProducerError::UnsupportedImport);
        assert!(!error.to_string().contains("bad$name"));
    }

    #[test]
    fn ordinal_only_import_rejects_the_complete_artifact() {
        let artifact = pe32_plus_fixture(&[TestThunk::Ordinal(42)]);
        let error = match produce_pe_api_import_bundle(&artifact, 0) {
            Err(error) => error,
            Ok(_) => panic!("ordinal-only import must fail closed"),
        };
        assert_eq!(error, PeApiImportProducerError::UnsupportedImport);
        assert!(!error.to_string().contains("42"));

        let mixed = pe32_plus_fixture(&[
            TestThunk::Name(b"ReadFile"),
            TestThunk::Ordinal(42),
            TestThunk::Name(b"VirtualAlloc"),
        ]);
        assert!(matches!(
            produce_pe_api_import_bundle(&mixed, 0),
            Err(PeApiImportProducerError::UnsupportedImport)
        ));
    }

    #[test]
    fn pe32_and_pe32_plus_dispatch_use_arch_specific_thunks() {
        let pe32 = pe32_fixture(&[
            TestThunk::Name(b"ReadFile"),
            TestThunk::Name(b"CreateFileA"),
        ]);
        let pe32_plus = pe32_plus_fixture(&[
            TestThunk::Name(b"ReadFile"),
            TestThunk::Name(b"CreateFileA"),
        ]);

        for artifact in [&pe32, &pe32_plus] {
            let bundle =
                produce_pe_api_import_bundle(artifact, 0).expect("valid architecture-specific PE");
            assert_eq!(bundle.observables()[0].value(), "CreateFileA");
        }
        assert!(matches!(
            produce_pe_api_import_bundle(&pe32_fixture(&[TestThunk::Ordinal(42)]), 0),
            Err(PeApiImportProducerError::UnsupportedImport)
        ));
    }

    #[test]
    fn multiple_libraries_dedupe_imports_without_disclosing_library_names() {
        let kernel32_thunks = [
            TestThunk::Name(b"ReadFile"),
            TestThunk::Name(b"CreateFileW"),
        ];
        let user32_thunks = [
            TestThunk::Name(b"MessageBoxW"),
            TestThunk::Name(b"CreateFileW"),
        ];
        let artifact = pe32_plus_multi_library_fixture(&[
            TestImportLibrary {
                name: b"KERNEL32.dll",
                thunks: &kernel32_thunks,
            },
            TestImportLibrary {
                name: b"USER32.dll",
                thunks: &user32_thunks,
            },
        ]);
        let expected = ["CreateFileW", "MessageBoxW", "ReadFile"];

        for (index, expected_import) in expected.into_iter().enumerate() {
            let bundle =
                produce_pe_api_import_bundle(&artifact, index).expect("valid multi-library PE");
            assert_eq!(bundle.observables()[0].value(), expected_import);
            let wire = String::from_utf8(bundle.to_canonical_bytes().expect("canonical bundle"))
                .expect("canonical UTF-8");
            assert!(!wire.contains("KERNEL32.dll"));
            assert!(!wire.contains("USER32.dll"));
        }
    }

    #[test]
    fn malformed_descriptor_fields_fail_closed() {
        let mut missing_thunks = named_fixture(&[b"ReadFile"]);
        write_u32(&mut missing_thunks, SECTION_DATA_OFFSET, 0);
        write_u32(&mut missing_thunks, SECTION_DATA_OFFSET + 16, 0);
        assert!(matches!(
            produce_pe_api_import_bundle(&missing_thunks, 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));

        let mut empty_library = named_fixture(&[b"ReadFile"]);
        let null_thunk_rva = SECTION_RVA
            + u32::try_from(2 * IMPORT_DESCRIPTOR_BYTES + PE32_PLUS_THUNK_BYTES)
                .expect("test null thunk RVA");
        write_u32(&mut empty_library, SECTION_DATA_OFFSET + 12, null_thunk_rva);
        assert!(matches!(
            produce_pe_api_import_bundle(&empty_library, 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));
    }

    #[test]
    fn bound_iat_without_unbound_lookup_table_fails_closed() {
        let mut bound_iat = named_fixture(&[b"ReadFile"]);
        write_u32(&mut bound_iat, SECTION_DATA_OFFSET, 0);
        write_u32(&mut bound_iat, SECTION_DATA_OFFSET + 4, 1);

        assert!(matches!(
            produce_pe_api_import_bundle(&bound_iat, 0),
            Err(PeApiImportProducerError::InvalidArtifact)
        ));
    }

    #[test]
    fn unbound_iat_fallback_without_lookup_table_remains_supported() {
        let mut unbound_iat = named_fixture(&[b"ReadFile"]);
        write_u32(&mut unbound_iat, SECTION_DATA_OFFSET, 0);

        let bundle =
            produce_pe_api_import_bundle(&unbound_iat, 0).expect("valid unbound IAT fallback");
        assert_eq!(bundle.observables()[0].value(), "ReadFile");
    }

    #[test]
    fn oversized_input_rejects_before_parsing() {
        let artifact = vec![0; MAX_PE_API_IMPORT_ARTIFACT_BYTES + 1];
        assert!(matches!(
            produce_pe_api_import_bundle(&artifact, 0),
            Err(PeApiImportProducerError::ArtifactTooLarge)
        ));
    }

    #[test]
    fn import_count_budget_rejects_before_sorting() {
        let imports = vec![b"ReadFile".as_slice(); MAX_PE_IMPORTS + 1];
        assert!(matches!(
            produce_pe_api_import_bundle(&named_fixture(&imports), 0),
            Err(PeApiImportProducerError::TooManyImports)
        ));
    }
}
