use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

pub(crate) const MAGIC: &[u8; 8] = b"FZBNDL1\0";
pub(crate) const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ENTRIES: usize = 64;
pub(crate) const MAX_NAME_BYTES: usize = 240;
pub(crate) const MAX_NAME_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BundleEntry<'a> {
    name: &'a str,
    data: &'a [u8],
}

impl<'a> BundleEntry<'a> {
    pub(crate) fn name(&self) -> &'a str {
        self.name
    }

    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }
}

#[derive(Debug)]
pub(crate) struct StagedBundle {
    root: PathBuf,
    #[cfg(target_os = "linux")]
    parent_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    root_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    directory_name: String,
    #[cfg(target_os = "linux")]
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl StagedBundle {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for StagedBundle {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        linux_staging::cleanup_owned_root(
            &self.parent_fd,
            &self.root_fd,
            &self.directory_name,
            self.identity,
        );
    }
}

fn read_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| format!("FZB1 {label} length overflows address space"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| format!("truncated FZB1 {label}"))?;
    *offset = end;
    Ok(value)
}

fn validate_name(name: &[u8]) -> Result<&str, String> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(format!(
            "FZB1 entry name length must be 1..={MAX_NAME_BYTES} bytes"
        ));
    }
    if !name.is_ascii() {
        return Err("FZB1 entry name must be ASCII".to_string());
    }
    let name = std::str::from_utf8(name).map_err(|_| "FZB1 entry name must be ASCII")?;
    let segments = name.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_NAME_DEPTH {
        return Err(format!("FZB1 entry name depth must be <= {MAX_NAME_DEPTH}"));
    }
    for segment in segments {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("FZB1 entry name contains a non-canonical segment".to_string());
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err("FZB1 entry name contains a forbidden byte".to_string());
        }
    }
    Ok(name)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<BundleEntry<'_>>, String> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "FZB1 input exceeds the {MAX_BUNDLE_BYTES}-byte limit"
        ));
    }
    let mut offset = 0usize;
    if read_exact(bytes, &mut offset, MAGIC.len(), "magic")? != MAGIC {
        return Err("invalid FZB1 magic".to_string());
    }
    let count = u32::from_le_bytes(
        read_exact(bytes, &mut offset, 4, "entry count")?
            .try_into()
            .expect("fixed entry-count width"),
    ) as usize;
    if !(1..=MAX_ENTRIES).contains(&count) {
        return Err(format!("FZB1 entry count must be 1..={MAX_ENTRIES}"));
    }

    let mut entries = Vec::with_capacity(count);
    let mut previous_name: Option<&[u8]> = None;
    let mut seen_names: Vec<&[u8]> = Vec::with_capacity(count);
    for index in 0..count {
        let name_len = u16::from_le_bytes(
            read_exact(bytes, &mut offset, 2, "entry name length")?
                .try_into()
                .expect("fixed name-length width"),
        ) as usize;
        let data_len_u64 = u64::from_le_bytes(
            read_exact(bytes, &mut offset, 8, "entry data length")?
                .try_into()
                .expect("fixed data-length width"),
        );
        let data_len = usize::try_from(data_len_u64)
            .map_err(|_| format!("FZB1 entry {index} data length does not fit usize"))?;
        let name_bytes = read_exact(bytes, &mut offset, name_len, "entry name")?;
        let name = validate_name(name_bytes)?;
        if let Some(previous) = previous_name {
            if name_bytes == previous {
                return Err(format!("duplicate FZB1 entry name: {name}"));
            }
            if name_bytes < previous {
                return Err(format!(
                    "FZB1 entries are not in canonical byte order: {name}"
                ));
            }
        }
        for (index, byte) in name_bytes.iter().enumerate() {
            if *byte == b'/' && seen_names.contains(&&name_bytes[..index]) {
                return Err(format!(
                    "FZB1 entry names conflict as file and directory: {name}"
                ));
            }
        }
        let data = read_exact(bytes, &mut offset, data_len, "entry data")?;
        entries.push(BundleEntry { name, data });
        previous_name = Some(name_bytes);
        seen_names.push(name_bytes);
    }
    if offset != bytes.len() {
        return Err("trailing bytes after the final FZB1 entry".to_string());
    }
    Ok(entries)
}

pub(crate) fn decode_with_allowlist<'a>(
    bytes: &'a [u8],
    allowlist: &[&str],
) -> Result<Vec<BundleEntry<'a>>, String> {
    let mut allowed = BTreeSet::new();
    for name in allowlist {
        validate_name(name.as_bytes())?;
        if !allowed.insert(*name) {
            return Err(format!("duplicate FZB1 allowlist entry: {name}"));
        }
    }
    if allowed.is_empty() || allowed.len() > MAX_ENTRIES {
        return Err(format!("FZB1 allowlist size must be 1..={MAX_ENTRIES}"));
    }

    let entries = decode(bytes)?;
    let actual = entries
        .iter()
        .map(BundleEntry::name)
        .collect::<BTreeSet<_>>();
    if actual != allowed {
        let missing = allowed.difference(&actual).copied().collect::<Vec<_>>();
        let unexpected = actual.difference(&allowed).copied().collect::<Vec<_>>();
        return Err(format!(
            "FZB1 entries do not match target allowlist (missing: {missing:?}, unexpected: {unexpected:?})"
        ));
    }
    Ok(entries)
}

pub(crate) fn encode(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, String> {
    if !(1..=MAX_ENTRIES).contains(&entries.len()) {
        return Err(format!("FZB1 entry count must be 1..={MAX_ENTRIES}"));
    }
    let mut ordered = entries.to_vec();
    for (name, _) in &ordered {
        validate_name(name.as_bytes())?;
    }
    ordered.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut seen_names = BTreeSet::new();
    for (name, _) in &ordered {
        if !seen_names.insert(*name) {
            return Err(format!("duplicate FZB1 entry name: {name}"));
        }
        for (index, byte) in name.bytes().enumerate() {
            if byte == b'/' && seen_names.contains(&name[..index]) {
                return Err(format!(
                    "FZB1 entry names conflict as file and directory: {name}"
                ));
            }
        }
    }

    let mut total = MAGIC.len() + 4;
    for (name, data) in &ordered {
        total = total
            .checked_add(2 + 8)
            .and_then(|value| value.checked_add(name.len()))
            .and_then(|value| value.checked_add(data.len()))
            .ok_or_else(|| "FZB1 encoded length overflows address space".to_string())?;
        if total > MAX_BUNDLE_BYTES {
            return Err(format!(
                "FZB1 output exceeds the {MAX_BUNDLE_BYTES}-byte limit"
            ));
        }
    }

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    for (name, data) in ordered {
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(data);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
mod linux_staging {
    use super::{validate_name, BundleEntry, FileIdentity};
    use std::{
        ffi::{CString, OsStr},
        fs::{self, File},
        io::{self, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            raw::{c_char, c_int, c_uint},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, Path, PathBuf},
    };

    const O_RDONLY: c_int = 0;
    const O_WRONLY: c_int = 1;
    const O_CREAT: c_int = 0o100;
    const O_EXCL: c_int = 0o200;
    const O_DIRECTORY: c_int = 0o200000;
    const O_NOFOLLOW: c_int = 0o400000;
    const O_CLOEXEC: c_int = 0o2000000;
    const O_PATH: c_int = 0o10000000;
    const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
    const AT_REMOVEDIR: c_int = 0x200;

    unsafe extern "C" {
        fn open(pathname: *const c_char, flags: c_int, ...) -> c_int;
        fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
        fn mkdirat(dirfd: c_int, pathname: *const c_char, mode: c_uint) -> c_int;
        fn fchmod(fd: c_int, mode: c_uint) -> c_int;
        fn fchmodat(dirfd: c_int, pathname: *const c_char, mode: c_uint, flags: c_int) -> c_int;
        fn unlinkat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int;
    }

    fn c_path(path: &Path) -> Result<CString, String> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("path contains NUL: {}", path.display()))
    }

    fn c_component(name: &OsStr) -> Result<CString, String> {
        CString::new(name.as_bytes()).map_err(|_| format!("path component contains NUL: {name:?}"))
    }

    fn c_name(name: &str) -> Result<CString, String> {
        c_component(OsStr::new(name))
    }

    fn owned_fd(fd: c_int, action: &str) -> Result<OwnedFd, String> {
        if fd < 0 {
            Err(format!("{action}: {}", io::Error::last_os_error()))
        } else {
            // SAFETY: a successful open/openat call returns one new descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn open_path_directory(path: &Path) -> Result<OwnedFd, String> {
        let path_c = c_path(path)?;
        // SAFETY: path_c is NUL-terminated and remains alive for the call.
        let fd = unsafe {
            open(
                path_c.as_ptr(),
                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        owned_fd(
            fd,
            &format!("failed to open directory '{}'", path.display()),
        )
    }

    fn open_component_at(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, String> {
        let name_c = c_component(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for this call.
        let fd = unsafe {
            openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        owned_fd(fd, &format!("failed to open directory component {name:?}"))
    }

    pub(super) fn open_directory(path: &Path) -> Result<OwnedFd, String> {
        let mut directory = if path.is_absolute() {
            open_path_directory(Path::new("/"))?
        } else {
            open_path_directory(Path::new("."))?
        };
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => directory = open_component_at(&directory, name)?,
                Component::ParentDir => {
                    return Err(format!(
                        "staging parent may not contain '..': {}",
                        path.display()
                    ));
                }
                Component::Prefix(_) => {
                    return Err(format!("unsupported staging parent: {}", path.display()));
                }
            }
        }
        Ok(directory)
    }

    pub(super) fn make_directory_at(
        parent: &OwnedFd,
        name: &str,
        allow_existing: bool,
    ) -> Result<bool, String> {
        let name_c = c_name(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for this call.
        let rc = unsafe { mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
        if rc == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if allow_existing && error.kind() == io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(format!(
                "failed to create staging directory {name:?}: {error}"
            ))
        }
    }

    pub(super) fn set_directory_mode_at(parent: &OwnedFd, name: &str) -> Result<(), String> {
        let name_c = c_name(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for this call. The no-follow flag
        // prevents a replaced directory name from redirecting chmod through a symlink.
        if unsafe {
            fchmodat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                0o700,
                AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(format!(
                "failed to set staging directory mode for {name:?}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(super) fn open_directory_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
        open_component_at(parent, OsStr::new(name))
    }

    pub(super) fn file_identity(fd: &OwnedFd) -> Result<FileIdentity, String> {
        let file = File::from(
            fd.try_clone()
                .map_err(|e| format!("failed to duplicate staging descriptor: {e}"))?,
        );
        let metadata = file
            .metadata()
            .map_err(|e| format!("failed to inspect staging descriptor: {e}"))?;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(super) fn name_matches_identity(
        parent: &OwnedFd,
        name: &str,
        expected: FileIdentity,
    ) -> bool {
        open_directory_at(parent, name)
            .and_then(|current| file_identity(&current))
            .ok()
            == Some(expected)
    }

    fn create_file_at(parent: &OwnedFd, name: &str) -> Result<File, String> {
        let name_c = c_name(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for this call. O_EXCL creates a
        // new regular file, and O_NOFOLLOW refuses a pre-planted symlink.
        let fd = unsafe {
            openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600 as c_uint,
            )
        };
        let fd = owned_fd(fd, &format!("failed to create staging file {name:?}"))?;
        if unsafe { fchmod(fd.as_raw_fd(), 0o600) } != 0 {
            return Err(format!(
                "failed to set staging file mode for {name:?}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(File::from(fd))
    }

    pub(super) fn write_entry(root: &OwnedFd, entry: BundleEntry<'_>) -> Result<(), String> {
        let segments = entry.name().split('/').collect::<Vec<_>>();
        let mut directory = root
            .try_clone()
            .map_err(|e| format!("failed to duplicate staging descriptor: {e}"))?;
        for segment in &segments[..segments.len() - 1] {
            let created = make_directory_at(&directory, segment, true)?;
            let next = open_directory_at(&directory, segment)?;
            if created {
                set_directory_mode_at(&directory, segment)?;
            }
            directory = next;
        }
        let filename = segments
            .last()
            .copied()
            .ok_or_else(|| "FZB1 entry has no filename".to_string())?;
        let mut file = create_file_at(&directory, filename)?;
        file.write_all(entry.data())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("failed to write staging file {filename:?}: {e}"))
    }

    pub(super) fn validate_directory_name(name: &str) -> Result<(), String> {
        validate_name(name.as_bytes())?;
        if name.contains('/') {
            return Err("staging directory name must be one canonical component".to_string());
        }
        Ok(())
    }

    pub(super) fn cleanup_owned_root(
        parent: &OwnedFd,
        root: &OwnedFd,
        name: &str,
        identity: FileIdentity,
    ) {
        // O_PATH lets creation survive a restrictive umask. Restore traversal permission through
        // the owned descriptor before removing children, even if the root was renamed meanwhile.
        let _ = set_directory_mode_at(root, ".");
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        if let Ok(children) = fs::read_dir(&descriptor_path) {
            for child in children.flatten() {
                let path = child.path();
                match child.file_type() {
                    Ok(kind) if kind.is_dir() && !kind.is_symlink() => {
                        let _ = fs::remove_dir_all(path);
                    }
                    Ok(_) => {
                        let _ = fs::remove_file(path);
                    }
                    Err(_) => {}
                }
            }
        }

        // Never apply pathname cleanup to a replacement. If the root was renamed, its contents
        // above are still cleaned through root's descriptor, while the unrelated replacement and
        // the now-empty moved directory are left intact.
        let Ok(current) = open_directory_at(parent, name) else {
            return;
        };
        if file_identity(&current).ok() != Some(identity) {
            return;
        }
        let Ok(name_c) = c_name(name) else {
            return;
        };
        // SAFETY: parent is open and name_c is NUL-terminated. The identity was checked above;
        // unlinkat only removes an empty directory and never traverses it.
        let _ = unsafe { unlinkat(parent.as_raw_fd(), name_c.as_ptr(), AT_REMOVEDIR) };
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn stage_bundle(
    bytes: &[u8],
    parent: &Path,
    directory_name: &str,
    allowlist: &[&str],
) -> Result<StagedBundle, String> {
    let entries = decode_with_allowlist(bytes, allowlist)?;
    linux_staging::validate_directory_name(directory_name)?;
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve staging parent: {e}"))?
            .join(parent)
    };
    let parent_fd = linux_staging::open_directory(&parent)?;
    linux_staging::make_directory_at(&parent_fd, directory_name, false)?;
    let root_path = parent.join(directory_name);
    let root_fd = linux_staging::open_directory_at(&parent_fd, directory_name)?;
    let identity = linux_staging::file_identity(&root_fd)?;
    let staged = StagedBundle {
        root: root_path,
        parent_fd,
        root_fd,
        directory_name: directory_name.to_string(),
        identity,
    };
    linux_staging::set_directory_mode_at(&staged.parent_fd, directory_name)?;
    if !linux_staging::name_matches_identity(&staged.parent_fd, directory_name, identity) {
        return Err("staging root changed during creation".to_string());
    }
    for entry in entries {
        linux_staging::write_entry(&staged.root_fd, entry)?;
    }
    if !linux_staging::name_matches_identity(&staged.parent_fd, directory_name, identity) {
        return Err("staging root changed during write".to_string());
    }
    Ok(staged)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn stage_bundle(
    _bytes: &[u8],
    _parent: &Path,
    _directory_name: &str,
    _allowlist: &[&str],
) -> Result<StagedBundle, String> {
    Err("FZB1 staging requires Linux".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn raw_bundle(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (name, data) in entries {
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(data);
        }
        bytes
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tool-model-bundle-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn golden_encoding_is_stable() {
        let encoded = encode(&[("b", b"XY"), ("a", b"")]).expect("encode golden bundle");
        let expected = [
            "465a424e444c3100",
            "02000000",
            "0100000000000000000061",
            "01000200000000000000625859",
        ]
        .concat();
        assert_eq!(
            encoded
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            expected
        );
    }

    #[test]
    fn round_trip_preserves_normal_and_empty_entries() {
        let encoded = encode(&[("model.xml", b"<net/>"), ("model.bin", b"")]).expect("encode");
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0],
            BundleEntry {
                name: "model.bin",
                data: b""
            }
        );
        assert_eq!(
            decoded[1],
            BundleEntry {
                name: "model.xml",
                data: b"<net/>"
            }
        );
    }

    #[test]
    fn rejects_truncated_header_and_entry_sections() {
        let valid = raw_bundle(&[(b"a", b"xyz")]);
        for end in 0..valid.len() {
            assert!(
                decode(&valid[..end]).is_err(),
                "accepted prefix length {end}"
            );
        }
        assert!(decode(&valid).is_ok());
    }

    #[test]
    fn rejects_bad_magic_and_entry_count_bounds() {
        let mut bad_magic = raw_bundle(&[(b"a", b"")]);
        bad_magic[7] = b'X';
        assert!(decode(&bad_magic).is_err());
        assert!(decode(&raw_bundle(&[])).is_err());
        let entries = (0..65)
            .map(|i| (format!("n{i:02}"), Vec::<u8>::new()))
            .collect::<Vec<_>>();
        let borrowed = entries
            .iter()
            .map(|(name, data)| (name.as_bytes(), data.as_slice()))
            .collect::<Vec<_>>();
        assert!(decode(&raw_bundle(&borrowed)).is_err());
    }

    #[test]
    fn rejects_declared_length_overflow() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.push(b'a');
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_duplicate_and_out_of_order_names() {
        assert!(decode(&raw_bundle(&[(b"a", b"1"), (b"a", b"2")])).is_err());
        assert!(decode(&raw_bundle(&[(b"b", b"1"), (b"a", b"2")])).is_err());
        assert!(decode(&raw_bundle(&[(b"a", b"1"), (b"a/b", b"2")])).is_err());
        assert!(decode(&raw_bundle(&[(b"a", b"1"), (b"a-", b"2"), (b"a/b", b"3")])).is_err());
        assert!(encode(&[("a", b"1"), ("a-", b"2"), ("a/b", b"3")]).is_err());
    }

    #[test]
    fn rejects_noncanonical_names() {
        let invalid: &[&[u8]] = &[
            b"",
            b"/abs",
            b"a/",
            b"a//b",
            b".",
            b"..",
            b"a/../b",
            b"a\\b",
            b"C:drive",
            b"bad name",
            b"bad\0name",
            b"nonascii\xff",
            b"a/b/c/d/e/f/g/h/i",
        ];
        for name in invalid {
            assert!(
                decode(&raw_bundle(&[(name, b"")])).is_err(),
                "accepted {name:?}"
            );
        }
        let long = vec![b'a'; MAX_NAME_BYTES + 1];
        assert!(decode(&raw_bundle(&[(&long, b"")])).is_err());
        assert!(decode(&raw_bundle(&[(b".hidden", b"")])).is_ok());
        assert!(decode(&raw_bundle(&[(b"a/b/c/d/e/f/g/h", b"")])).is_ok());
    }

    #[test]
    fn rejects_trailing_bytes_and_oversized_input() {
        let mut trailing = raw_bundle(&[(b"a", b"")]);
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let oversized = vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert!(decode(&oversized).is_err());
    }

    #[test]
    fn allowlist_requires_an_exact_case_sensitive_set() {
        let bytes = raw_bundle(&[(b"model.bin", b"B"), (b"model.xml", b"X")]);
        assert!(decode_with_allowlist(&bytes, &["model.xml", "model.bin"]).is_ok());
        assert!(decode_with_allowlist(&bytes, &["model.xml"]).is_err());
        assert!(decode_with_allowlist(&bytes, &["model.xml", "model.bin", "extra"]).is_err());
        assert!(decode_with_allowlist(&bytes, &["MODEL.BIN", "model.xml"]).is_err());
        assert!(decode_with_allowlist(&bytes, &["model.bin", "model.bin"]).is_err());
    }

    #[test]
    fn staging_creates_private_files_and_preserves_input() {
        use std::os::unix::fs::PermissionsExt;

        let parent = temp_dir("stage");
        fs::create_dir(&parent).expect("create parent");
        let bytes = raw_bundle(&[(b"nested/empty", b""), (b"nested/value", b"payload")]);
        let original = bytes.clone();
        let staged = stage_bundle(
            &bytes,
            &parent,
            "input-1",
            &["nested/value", "nested/empty"],
        )
        .expect("stage");
        assert_eq!(bytes, original);
        assert_eq!(
            fs::read(staged.root().join("nested/value")).unwrap(),
            b"payload"
        );
        assert_eq!(fs::read(staged.root().join("nested/empty")).unwrap(), b"");
        assert_eq!(
            fs::metadata(staged.root()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(staged.root().join("nested/value"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let root = staged.root().to_path_buf();
        drop(staged);
        assert!(!root.exists());
        fs::remove_dir(&parent).expect("remove parent");
    }

    #[test]
    fn staging_refuses_symlink_parent_and_existing_destination() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("symlink");
        let real = root.join("real");
        let alias = root.join("alias");
        fs::create_dir_all(&real).expect("create real parent");
        symlink(&real, &alias).expect("create parent symlink");
        let bytes = raw_bundle(&[(b"file", b"data")]);
        assert!(stage_bundle(&bytes, &alias, "input", &["file"]).is_err());
        fs::create_dir(real.join("input")).expect("preplant destination");
        assert!(stage_bundle(&bytes, &real, "input", &["file"]).is_err());
        assert!(real.join("input").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn staging_refuses_symlink_in_an_intermediate_parent_component() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("parent-component-symlink");
        let intended = root.join("intended");
        let outside = root.join("outside");
        fs::create_dir_all(&intended).expect("create intended parent");
        fs::create_dir_all(outside.join("sub")).expect("create outside parent");
        symlink(&outside, intended.join("link")).expect("plant parent symlink");
        let bytes = raw_bundle(&[(b"file", b"must-not-escape")]);

        assert!(stage_bundle(&bytes, &intended.join("link/sub"), "stage", &["file"]).is_err());
        assert!(!outside.join("sub/stage").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn staging_rejects_invalid_directory_component_before_writing() {
        let parent = temp_dir("component");
        fs::create_dir(&parent).expect("create parent");
        let bytes = raw_bundle(&[(b"file", b"data")]);
        for name in ["", ".", "..", "nested/path", "back\\slash"] {
            assert!(stage_bundle(&bytes, &parent, name, &["file"]).is_err());
        }
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        fs::remove_dir(&parent).expect("cleanup");
    }

    #[test]
    fn staging_does_not_follow_a_preplanted_intermediate_symlink() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("intermediate-symlink");
        let stage = root.join("stage");
        let outside = root.join("outside");
        fs::create_dir_all(&stage).expect("create stage");
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("sentinel"), b"unchanged").expect("write sentinel");
        symlink(&outside, stage.join("nested")).expect("plant intermediate symlink");

        let root_fd = linux_staging::open_directory(&stage).expect("open stage");
        let entry = BundleEntry {
            name: "nested/payload",
            data: b"must-not-escape",
        };
        assert!(linux_staging::write_entry(&root_fd, entry).is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert!(!outside.join("payload").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn staging_cleanup_never_deletes_a_replacement_directory() {
        let parent = temp_dir("root-replacement");
        fs::create_dir(&parent).expect("create parent");
        let bytes = raw_bundle(&[(b"file", b"owned")]);
        let staged = stage_bundle(&bytes, &parent, "stage", &["file"]).expect("stage");
        let moved = parent.join("moved-owned-root");
        fs::rename(staged.root(), &moved).expect("move owned root");
        fs::create_dir(parent.join("stage")).expect("create replacement");
        fs::write(parent.join("stage/victim"), b"unrelated").expect("write replacement file");

        drop(staged);

        assert_eq!(fs::read(parent.join("stage/victim")).unwrap(), b"unrelated");
        assert!(!moved.join("file").exists());
        fs::remove_dir_all(&parent).expect("cleanup");
    }
}
