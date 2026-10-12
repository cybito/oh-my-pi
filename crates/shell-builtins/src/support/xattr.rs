//! Extended-attribute probes for `ls` and `mkdir`, and no-follow copies for
//! `mv` on Linux and Android.

#[cfg(all(unix, not(target_os = "macos")))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{ffi, ffi::OsString, io, ptr};

#[cfg(any(target_os = "linux", target_os = "android"))]
use omp_core::FastHashMap;

/// Returns whether a path has at least one extended ACL or attribute.
#[cfg(all(unix, not(any(target_os = "android", target_os = "macos"))))]
pub(crate) fn has_acl(path: impl AsRef<Path>) -> bool {
	#[cfg(target_os = "linux")]
	return list_xattrs(path.as_ref()).is_ok_and(|names| !names.is_empty());
	#[cfg(not(target_os = "linux"))]
	{
		let _ = path;
		false
	}
}

/// Returns whether Linux's `security.capability` extended attribute is present.
#[cfg(all(unix, not(any(target_os = "android", target_os = "macos"))))]
pub(crate) fn has_security_cap_acl(path: impl AsRef<Path>) -> bool {
	#[cfg(target_os = "linux")]
	return list_xattrs(path.as_ref()).is_ok_and(|names| {
		names
			.split(|byte| *byte == 0)
			.any(|name| name == b"security.capability")
	});
	#[cfg(not(target_os = "linux"))]
	{
		let _ = path;
		false
	}
}

/// Extracts inherited owner, group, and other permission bits from a Linux
/// default ACL.
#[cfg(target_os = "linux")]
pub(crate) fn get_acl_perm_bits_from_xattr(path: impl AsRef<Path>) -> u32 {
	get_xattr(path.as_ref(), b"system.posix_acl_default\0")
		.ok()
		.and_then(|value| parse_default_acl_permissions(&value))
		.unwrap_or(0)
}

/// Reads name/value pairs without following a final symlink.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn retrieve_xattrs(
	path: impl AsRef<Path>,
) -> io::Result<FastHashMap<OsString, Vec<u8>>> {
	use std::os::unix::ffi::OsStringExt as _;

	let path = path_cstring(path.as_ref())?;
	let names = list_link_xattrs(&path)?;
	let mut attrs = FastHashMap::default();
	for name in xattr_names(&names) {
		let name = name?;
		if let Some(value) = get_link_xattr(&path, name)? {
			attrs.insert(OsString::from_vec(name.to_bytes().to_vec()), value);
		}
	}
	Ok(attrs)
}

/// Applies name/value pairs without following a final symlink.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn apply_xattrs(
	path: impl AsRef<Path>,
	xattrs: FastHashMap<OsString, Vec<u8>>,
) -> io::Result<()> {
	use std::os::unix::ffi::OsStringExt as _;

	let path = path_cstring(path.as_ref())?;
	for (name, value) in xattrs {
		let name = ffi::CString::new(name.into_vec()).map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidInput, "attribute name contains a NUL byte")
		})?;
		set_link_xattr(&path, &name, &value)?;
	}
	Ok(())
}

/// Copies listed attributes without following either final symlink.
///
/// Attributes removed during retrieval are skipped; other errors are returned
/// unchanged. Attributes already on the destination are not removed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn copy_xattrs(source: impl AsRef<Path>, dest: impl AsRef<Path>) -> io::Result<()> {
	let source = path_cstring(source.as_ref())?;
	let dest = path_cstring(dest.as_ref())?;
	let names = list_link_xattrs(&source)?;
	for name in xattr_names(&names) {
		let name = name?;
		if let Some(value) = get_link_xattr(&source, name)? {
			set_link_xattr(&dest, name, &value)?;
		}
	}
	Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn path_cstring(path: &Path) -> io::Result<ffi::CString> {
	use std::os::unix::ffi::OsStrExt;
	ffi::CString::new(path.as_os_str().as_bytes())
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

#[cfg(target_os = "linux")]
fn list_xattrs(path: &Path) -> io::Result<Vec<u8>> {
	let path = path_cstring(path)?;
	// SAFETY: the C path is valid and a null buffer with length zero performs a
	// size query.
	let size = unsafe { libc::listxattr(path.as_ptr(), ptr::null_mut(), 0) };
	if size < 0 {
		return Err(io::Error::last_os_error());
	}
	if size == 0 {
		return Ok(Vec::new());
	}
	let mut names = vec![0_u8; size as usize];
	// SAFETY: `names` is writable for its full reported capacity.
	let read = unsafe { libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
	if read < 0 {
		return Err(io::Error::last_os_error());
	}
	names.truncate(read as usize);
	Ok(names)
}

#[cfg(target_os = "linux")]
fn get_xattr(path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
	let path = path_cstring(path)?;
	let name = ffi::CStr::from_bytes_with_nul(name)
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid attribute name"))?;
	// SAFETY: both C strings are valid; a null value pointer performs a size query.
	let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), ptr::null_mut(), 0) };
	if size < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut value = vec![0_u8; size as usize];
	// SAFETY: `value` is writable for the queried size and all pointers remain
	// live.
	let read = unsafe {
		libc::getxattr(path.as_ptr(), name.as_ptr(), value.as_mut_ptr().cast(), value.len())
	};
	if read < 0 {
		return Err(io::Error::last_os_error());
	}
	value.truncate(read as usize);
	Ok(value)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn xattr_names(names: &[u8]) -> impl Iterator<Item = io::Result<&ffi::CStr>> {
	names.split_inclusive(|byte| *byte == 0).map(|name| {
		ffi::CStr::from_bytes_with_nul(name)
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid attribute name"))
	})
}

/// Performs at most four size-query/read attempts while retaining the buffer.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_xattr_buffer(
	mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<Vec<u8>> {
	let mut buffer = Vec::new();
	let mut retries = 3;
	loop {
		let result: io::Result<()> = (|| {
			let size = read(&mut [])?;
			if size == 0 {
				// A nonempty scratch read detects growth without allocating
				// for the common case of an empty list or attribute value.
				let mut scratch = [0_u8];
				let size = read(&mut scratch)?;
				buffer.clear();
				buffer.extend_from_slice(&scratch[..size]);
			} else {
				buffer.resize(size, 0);
				let size = read(&mut buffer)?;
				buffer.truncate(size);
			}
			Ok(())
		})();
		match result {
			Ok(()) => return Ok(buffer),
			Err(error) if error.raw_os_error() == Some(libc::ERANGE) && retries > 0 => {
				retries -= 1;
			},
			Err(error) => return Err(error),
		}
	}
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn list_link_xattrs(path: &ffi::CStr) -> io::Result<Vec<u8>> {
	read_xattr_buffer(|buffer| {
		let names = if buffer.is_empty() { ptr::null_mut() } else { buffer.as_mut_ptr().cast() };
		// SAFETY: the C path is valid; the buffer is writable for its length,
		// or null with length zero for a size query.
		let read = unsafe { libc::llistxattr(path.as_ptr(), names, buffer.len()) };
		if read < 0 { Err(io::Error::last_os_error()) } else { Ok(read as usize) }
	})
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_link_xattr(path: &ffi::CStr, name: &ffi::CStr) -> io::Result<Option<Vec<u8>>> {
	let result = read_xattr_buffer(|buffer| {
		let value = if buffer.is_empty() { ptr::null_mut() } else { buffer.as_mut_ptr().cast() };
		// SAFETY: both C strings are valid; the buffer is writable for its
		// length, or null with length zero for a size query.
		let read = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), value, buffer.len()) };
		if read < 0 { Err(io::Error::last_os_error()) } else { Ok(read as usize) }
	});
	match result {
		Ok(value) => Ok(Some(value)),
		// Disappearance during either the size query or the read must not
		// discard the other attributes in the caller's list.
		Err(error) if error.raw_os_error() == Some(libc::ENODATA) => Ok(None),
		Err(error) => Err(error),
	}
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_link_xattr(path: &ffi::CStr, name: &ffi::CStr, value: &[u8]) -> io::Result<()> {
	// SAFETY: both C strings are valid and `value` is readable for its length.
	let written = unsafe {
		libc::lsetxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0)
	};
	if written < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(target_os = "linux")]
fn parse_default_acl_permissions(value: &[u8]) -> Option<u32> {
	const ACL_USER_OBJ: u16 = 0x01;
	const ACL_GROUP_OBJ: u16 = 0x04;
	const ACL_MASK: u16 = 0x10;
	const ACL_OTHER: u16 = 0x20;
	if value.len() < 4 || u32::from_le_bytes(value[..4].try_into().ok()?) != 2 {
		return None;
	}
	let mut owner = None;
	let mut group = None;
	let mut mask = None;
	let mut other = None;
	for entry in value[4..].chunks_exact(8) {
		let tag = u16::from_le_bytes([entry[0], entry[1]]);
		let permissions = u32::from(u16::from_le_bytes([entry[2], entry[3]]) & 0o7);
		match tag {
			ACL_USER_OBJ => owner = Some(permissions),
			ACL_GROUP_OBJ => group = Some(permissions),
			ACL_MASK => mask = Some(permissions),
			ACL_OTHER => other = Some(permissions),
			_ => {},
		}
	}
	Some((owner? << 6) | (mask.or(group)? << 3) | other?)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
	use super::*;
	use std::{fs, io::Write as _, os::unix::ffi::OsStringExt as _};

	fn set_test_attr(path: &Path, name: &ffi::CStr, value: &[u8]) -> bool {
		match set_link_xattr(&path_cstring(path).unwrap(), name, value) {
			Ok(()) => true,
			Err(error)
				if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) =>
			{
				writeln!(
					io::stderr().lock(),
					"SKIP xattr: 临时目录不支持扩展属性（{}）：{error}",
					path.display()
				)
				.unwrap();
				false
			},
			Err(error) => panic!("set test attribute on {}: {error}", path.display()),
		}
	}

	#[test]
	fn retries_query_and_read_growth_including_an_empty_value() {
		let mut calls = 0;
		let value = read_xattr_buffer(|buffer| {
			calls += 1;
			match calls {
				1 => {
					assert!(buffer.is_empty());
					Err(io::Error::from_raw_os_error(libc::ERANGE))
				},
				2 => Ok(0),
				3 => {
					assert_eq!(buffer.len(), 1);
					Err(io::Error::from_raw_os_error(libc::ERANGE))
				},
				4 => Ok(3),
				5 => {
					buffer.copy_from_slice(b"\0\xff\0");
					Ok(3)
				},
				_ => panic!("unexpected extra read"),
			}
		})
		.unwrap();
		assert_eq!(value, b"\0\xff\0");
		assert_eq!(calls, 5);
	}

	#[test]
	fn bounds_growth_retries_and_preserves_errno() {
		for fail_query in [true, false] {
			let mut calls = 0;
			let error = read_xattr_buffer(|buffer| {
				calls += 1;
				if fail_query || !buffer.is_empty() {
					Err(io::Error::from_raw_os_error(libc::ERANGE))
				} else {
					Ok(1)
				}
			})
			.unwrap_err();
			assert_eq!(error.raw_os_error(), Some(libc::ERANGE));
			assert_eq!(calls, if fail_query { 4 } else { 8 });
		}
	}

	#[test]
	fn propagates_disappearance_from_either_read_phase_without_retrying() {
		for fail_query in [true, false] {
			let mut calls = 0;
			let error = read_xattr_buffer(|buffer| {
				calls += 1;
				if fail_query || !buffer.is_empty() {
					Err(io::Error::from_raw_os_error(libc::ENODATA))
				} else {
					Ok(0)
				}
			})
			.unwrap_err();
			assert_eq!(error.raw_os_error(), Some(libc::ENODATA));
			assert_eq!(calls, if fail_query { 1 } else { 2 });
		}
	}

	#[test]
	fn retrieves_applies_and_copies_binary_and_empty_values() {
		let fixture = tempfile::tempdir().unwrap();
		let source = fixture.path().join(OsString::from_vec(b"source-\xff".to_vec()));
		let applied = fixture.path().join("applied");
		let copied = fixture.path().join("copied");
		for path in [&source, &applied, &copied] {
			fs::write(path, b"payload").unwrap();
		}
		let binary_name = ffi::CStr::from_bytes_with_nul(b"user.omp.\xff\0").unwrap();
		if !set_test_attr(&source, binary_name, b"\0\xffbinary\0") {
			return;
		}
		assert!(set_test_attr(&source, c"user.omp.empty", b""));
		assert!(set_test_attr(&copied, c"user.omp.destination", b"keep"));
		let binary_key = OsString::from_vec(binary_name.to_bytes().to_vec());
		let empty_key = OsString::from("user.omp.empty");
		let attrs = retrieve_xattrs(&source).unwrap();
		assert_eq!(attrs[&binary_key], b"\0\xffbinary\0");
		assert!(attrs[&empty_key].is_empty());
		apply_xattrs(&applied, attrs).unwrap();
		copy_xattrs(&source, &copied).unwrap();
		for path in [&applied, &copied] {
			let attrs = retrieve_xattrs(path).unwrap();
			assert_eq!(attrs[&binary_key], b"\0\xffbinary\0");
			assert!(attrs[&empty_key].is_empty());
		}
		assert_eq!(
			retrieve_xattrs(&copied).unwrap()[&OsString::from("user.omp.destination")],
			b"keep"
		);
	}

	#[test]
	fn a_disappeared_attribute_does_not_erase_remaining_values() {
		let fixture = tempfile::tempdir().unwrap();
		let source = fixture.path().join("source");
		fs::write(&source, b"payload").unwrap();
		if !set_test_attr(&source, c"user.omp.keep", b"\0keep\xff") {
			return;
		}
		assert!(set_test_attr(&source, c"user.omp.remove", b"remove"));
		let path = path_cstring(&source).unwrap();
		let names = list_link_xattrs(&path).unwrap();
		assert!(xattr_names(&names).any(|name| name.unwrap() == c"user.omp.remove"));
		// SAFETY: both C strings are valid and remain live for the call.
		assert_eq!(unsafe { libc::lremovexattr(path.as_ptr(), c"user.omp.remove".as_ptr()) }, 0);
		assert_eq!(get_link_xattr(&path, c"user.omp.remove").unwrap(), None);
		let attrs = retrieve_xattrs(&source).unwrap();
		assert_eq!(attrs[&OsString::from("user.omp.keep")], b"\0keep\xff");
		assert!(!attrs.contains_key(&OsString::from("user.omp.remove")));
	}

	#[test]
	fn copy_operations_do_not_follow_symlinks_but_acl_probes_still_do() {
		let fixture = tempfile::tempdir().unwrap();
		let source = fixture.path().join("source");
		let target = fixture.path().join("target");
		let link = fixture.path().join("link");
		let dangling = fixture.path().join("dangling");
		fs::write(&source, b"new").unwrap();
		fs::write(&target, b"old").unwrap();
		if !set_test_attr(&source, c"user.omp.value", b"new") {
			return;
		}
		assert!(set_test_attr(&target, c"user.omp.value", b"old"));
		std::os::unix::fs::symlink(&target, &link).unwrap();
		std::os::unix::fs::symlink(fixture.path().join("missing"), &dangling).unwrap();
		assert!(has_acl(&link));
		assert!(!retrieve_xattrs(&link).unwrap().contains_key(&OsString::from("user.omp.value")));
		retrieve_xattrs(&dangling).unwrap();
		// Linux forbids user attributes on symlinks. A no-follow write must
		// fail rather than silently overwrite the target's attribute.
		copy_xattrs(&source, &link).unwrap_err();
		let attrs = retrieve_xattrs(&source).unwrap();
		apply_xattrs(&link, attrs).unwrap_err();
		assert_eq!(retrieve_xattrs(&target).unwrap()[&OsString::from("user.omp.value")], b"old");
	}

	#[test]
	fn missing_paths_return_the_original_io_error() {
		let fixture = tempfile::tempdir().unwrap();
		let missing = fixture.path().join("missing");
		assert_eq!(retrieve_xattrs(&missing).unwrap_err().raw_os_error(), Some(libc::ENOENT));
		assert_eq!(
			copy_xattrs(&missing, fixture.path().join("target")).unwrap_err().raw_os_error(),
			Some(libc::ENOENT)
		);
		let mut attrs = FastHashMap::default();
		attrs.insert(OsString::from("user.omp.value"), b"value".to_vec());
		assert_eq!(apply_xattrs(&missing, attrs).unwrap_err().raw_os_error(), Some(libc::ENOENT));
	}

	#[test]
	fn parses_default_acl_mode_bits() {
		let mut value = 2_u32.to_le_bytes().to_vec();
		for (tag, permissions) in [(1_u16, 7_u16), (4, 5), (16, 4), (32, 1)] {
			value.extend_from_slice(&tag.to_le_bytes());
			value.extend_from_slice(&permissions.to_le_bytes());
			value.extend_from_slice(&u32::MAX.to_le_bytes());
		}
		assert_eq!(parse_default_acl_permissions(&value), Some(0o741));
	}
}
