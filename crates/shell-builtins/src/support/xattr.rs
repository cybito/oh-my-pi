//! Extended-attribute probes and preservation used by `ls`, `mkdir`, and `mv`.

#[cfg(all(unix, not(any(target_os = "android", target_os = "macos"))))]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{ffi, io, ptr};

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

#[cfg(target_os = "linux")]
fn path_cstring(path: &Path) -> io::Result<ffi::CString> {
	use std::os::unix::ffi::OsStrExt;
	ffi::CString::new(path.as_os_str().as_bytes())
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

#[cfg(target_os = "linux")]
fn list_xattrs(path: &Path) -> io::Result<Vec<u8>> {
	list_xattrs_cstr(&path_cstring(path)?)
}

#[cfg(target_os = "linux")]
fn list_xattrs_cstr(path: &ffi::CStr) -> io::Result<Vec<u8>> {
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
	let name = ffi::CStr::from_bytes_with_nul(name)
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid attribute name"))?;
	get_xattr_cstr(&path_cstring(path)?, name)
}

#[cfg(target_os = "linux")]
fn get_xattr_cstr(path: &ffi::CStr, name: &ffi::CStr) -> io::Result<Vec<u8>> {
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

#[cfg(target_os = "linux")]
fn set_xattr_cstr(path: &ffi::CStr, name: &ffi::CStr, value: &[u8]) -> io::Result<()> {
	// SAFETY: both C strings and the value buffer remain live for this call.
	let result = unsafe {
		libc::setxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0)
	};
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

/// Captures attributes before a cross-filesystem directory move.
#[cfg(target_os = "linux")]
pub(crate) fn retrieve_xattrs(
	path: impl AsRef<Path>,
) -> io::Result<omp_core::FastHashMap<ffi::CString, Vec<u8>>> {
	let path = path_cstring(path.as_ref())?;
	let names = list_xattrs_cstr(&path)?;
	let mut attributes = omp_core::FastHashMap::default();
	for name in names.split_inclusive(|byte| *byte == 0) {
		let name = ffi::CStr::from_bytes_with_nul(name)
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid attribute name"))?;
		attributes.insert(name.to_owned(), get_xattr_cstr(&path, name)?);
	}
	Ok(attributes)
}

/// Restores captured attributes without removing unrelated destination attributes.
#[cfg(target_os = "linux")]
pub(crate) fn apply_xattrs(
	path: impl AsRef<Path>,
	attributes: omp_core::FastHashMap<ffi::CString, Vec<u8>>,
) -> io::Result<()> {
	let path = path_cstring(path.as_ref())?;
	for (name, value) in attributes {
		set_xattr_cstr(&path, &name, &value)?;
	}
	Ok(())
}

/// Copies attributes using one value buffer at a time.
#[cfg(target_os = "linux")]
pub(crate) fn copy_xattrs(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
	let from = path_cstring(from.as_ref())?;
	let to = path_cstring(to.as_ref())?;
	let names = list_xattrs_cstr(&from)?;
	for name in names.split_inclusive(|byte| *byte == 0) {
		let name = ffi::CStr::from_bytes_with_nul(name)
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid attribute name"))?;
		let value = get_xattr_cstr(&from, name)?;
		set_xattr_cstr(&to, name, &value)?;
	}
	Ok(())
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

	#[test]
	fn preserves_binary_empty_and_unrelated_attributes() {
		let directory = tempfile::tempdir().unwrap();
		let from = directory.path().join("from");
		let to = directory.path().join("to");
		std::fs::write(&from, b"source").unwrap();
		std::fs::write(&to, b"destination").unwrap();
		let from_c = path_cstring(&from).unwrap();
		let to_c = path_cstring(&to).unwrap();
		let binary_name = c"user.omp2.binary";
		let empty_name = c"user.omp2.empty";
		let unrelated_name = c"user.omp2.unrelated";
		set_xattr_cstr(&from_c, binary_name, &[0, 255, 1]).unwrap();
		set_xattr_cstr(&from_c, empty_name, &[]).unwrap();
		set_xattr_cstr(&to_c, unrelated_name, b"keep").unwrap();
		copy_xattrs(&from, &to).unwrap();
		assert_eq!(get_xattr_cstr(&to_c, binary_name).unwrap(), [0, 255, 1]);
		assert_eq!(get_xattr_cstr(&to_c, empty_name).unwrap(), []);
		assert_eq!(get_xattr_cstr(&to_c, unrelated_name).unwrap(), b"keep");

		let source_directory = directory.path().join("source-directory");
		let destination_directory = directory.path().join("destination-directory");
		std::fs::create_dir(&source_directory).unwrap();
		std::fs::create_dir(&destination_directory).unwrap();
		set_xattr_cstr(&path_cstring(&source_directory).unwrap(), binary_name, &[1, 0, 128])
			.unwrap();
		let attributes = retrieve_xattrs(&source_directory).unwrap();
		std::fs::remove_dir(&source_directory).unwrap();
		apply_xattrs(&destination_directory, attributes).unwrap();
		assert_eq!(
			get_xattr_cstr(&path_cstring(&destination_directory).unwrap(), binary_name).unwrap(),
			[1, 0, 128]
		);
	}

	#[test]
	fn reports_missing_sources_and_destinations() {
		let directory = tempfile::tempdir().unwrap();
		let missing = directory.path().join("missing");
		assert_eq!(retrieve_xattrs(&missing).unwrap_err().kind(), io::ErrorKind::NotFound);
		let source = directory.path().join("source");
		std::fs::write(&source, b"data").unwrap();
		set_xattr_cstr(&path_cstring(&source).unwrap(), c"user.omp2.binary", &[0, 255]).unwrap();
		assert_eq!(copy_xattrs(&source, &missing).unwrap_err().kind(), io::ErrorKind::NotFound);
		assert_eq!(
			apply_xattrs(&missing, retrieve_xattrs(&source).unwrap()).unwrap_err().kind(),
			io::ErrorKind::NotFound
		);
	}
}
