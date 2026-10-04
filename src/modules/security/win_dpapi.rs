#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob_from(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    unsafe fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes =
            std::slice::from_raw_parts(out.pbData as *const u8, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut _));
        bytes
    }

    pub fn protect_bytes(plain: &[u8]) -> Result<Vec<u8>, String> {
        if plain.is_empty() {
            return Err("empty plaintext".to_string());
        }
        let mut out = CRYPT_INTEGER_BLOB::default();
        let in_blob = blob_from(plain);
        let hr = unsafe {
            CryptProtectData(
                &in_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if hr.is_err() {
            return Err(format!("DPAPI protect failed: {hr:?}"));
        }
        Ok(unsafe { take_blob(out) })
    }

    pub fn unprotect_bytes(sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.is_empty() {
            return Err("empty blob".to_string());
        }
        let in_blob = blob_from(sealed);
        let mut out = CRYPT_INTEGER_BLOB::default();
        let hr = unsafe {
            CryptUnprotectData(
                &in_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if hr.is_err() {
            return Err(format!("DPAPI unprotect failed: {hr:?}"));
        }
        Ok(unsafe { take_blob(out) })
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn protect_bytes(_plain: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI is only available on Windows".to_string())
    }

    pub fn unprotect_bytes(_sealed: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI is only available on Windows".to_string())
    }
}

pub use imp::{protect_bytes, unprotect_bytes};

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_bytes_roundtrip() {
        let key: [u8; 32] = [7u8; 32];
        let sealed = protect_bytes(&key).expect("protect must succeed for current user");
        assert_ne!(sealed, key);
        let recovered = unprotect_bytes(&sealed).expect("unprotect must succeed");
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_dpapi_bytes_rejects_garbage() {
        assert!(unprotect_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    }
}
