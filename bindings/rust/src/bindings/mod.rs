use core::mem::MaybeUninit;
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PublicKey(ctt_eth_bls_pubkey);

impl PublicKey {
    pub fn from_bytes(k: &[u8]) -> Self {
        let mut out = MaybeUninit::uninit();
        unsafe {
            match ctt_eth_bls_deserialize_pubkey_compressed(out.as_mut_ptr(), k.as_ptr()) as u8 {
                0 => {}
                _ => panic!("failed to deserialize public key"),
            }
            PublicKey(out.assume_init())
        }
    }

    pub fn is_zero(&self) -> bool {
        unsafe { ctt_eth_bls_pubkey_is_zero(&self.0 as *const ctt_eth_bls_pubkey) }
    }
}

impl From<ctt_eth_bls_pubkey> for PublicKey {
    fn from(k: ctt_eth_bls_pubkey) -> Self {
        PublicKey(k)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Signature(ctt_eth_bls_signature);

impl Signature {
    pub fn from_bytes(s: &[u8]) -> Self {
        let mut out = MaybeUninit::uninit();
        unsafe {
            match ctt_eth_bls_deserialize_signature_compressed(out.as_mut_ptr(), s.as_ptr()) as u8 {
                0 => {}
                _ => panic!("failed to deserialize signature"),
            }
            Signature(out.assume_init())
        }
    }

    pub fn is_zero(&self) -> bool {
        unsafe { ctt_eth_bls_signature_is_zero(&self.0 as *const ctt_eth_bls_signature) }
    }
}

impl From<ctt_eth_bls_signature> for Signature {
    fn from(s: ctt_eth_bls_signature) -> Self {
        Signature(s)
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), String> {
    unsafe {
        match ctt_eth_bls_verify(
            &public_key.0 as *const ctt_eth_bls_pubkey,
            msg.as_ptr(),
            msg.len() as isize,
            &signature.0 as *const ctt_eth_bls_signature,
        ) as u8
        {
            0 => Ok(()),
            e => Err(format!("failed to verify signature: {:?}", e)),
        }
    }
}

pub fn fast_aggregate_verify(
    public_keys: &[PublicKey],
    msg: &[u8],
    signature: &Signature,
) -> Result<(), String> {
    unsafe {
        ctt_eth_bls_init_NimMain();
        let pks = public_keys.iter().map(|x| x.0).collect::<Vec<_>>();
        match ctt_eth_bls_fast_aggregate_verify(
            pks.as_ptr(),
            pks.len() as isize,
            msg.as_ptr(),
            msg.len() as isize,
            &signature.0 as *const ctt_eth_bls_signature,
        ) as u8
        {
            0 => Ok(()),
            e => Err(format!("failed to verify signature: {:?}", e)),
        }
    }
}

pub mod sha256 {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Sha256Ctx(ctt_eth_bls_sha256_context);

    impl Sha256Ctx {
        pub fn init() -> Self {
            let mut out = MaybeUninit::uninit();
            unsafe {
                ctt_eth_bls_sha256_init(out.as_mut_ptr());
                Sha256Ctx(out.assume_init())
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            unsafe {
                ctt_eth_bls_sha256_update(
                    &mut self.0 as *mut ctt_eth_bls_sha256_context,
                    data.as_ptr(),
                    data.len() as isize,
                );
            }
        }
        pub fn finish(&mut self) -> [u8; 32] {
            let mut out = MaybeUninit::uninit();
            unsafe {
                ctt_eth_bls_sha256_finish(
                    &mut self.0 as *mut ctt_eth_bls_sha256_context,
                    out.as_mut_ptr() as *mut u8,
                );
                out.assume_init()
            }
        }
        pub fn clear(&mut self) {
            unsafe {
                ctt_eth_bls_sha256_clear(&mut self.0 as *mut ctt_eth_bls_sha256_context);
            }
        }
        pub fn hash(data: &[u8], clear: bool) -> [u8; 32] {
            let mut out = MaybeUninit::uninit();
            unsafe {
                ctt_eth_bls_sha256_hash(
                    out.as_mut_ptr() as *mut u8,
                    data.as_ptr(),
                    data.len() as isize,
                    clear,
                );
                out.assume_init()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        // Initialize the runtime. For Constantine, it populates the CPU runtime detection dispatch.
        unsafe { ctt_eth_bls_init_NimMain() };

        // Declare an example insecure non-cryptographically random non-secret key. DO NOT USE IN PRODUCTION.
        let raw_seckey: [u8; 32] = "Security pb becomes key mgmt pb!"
            .as_bytes()
            .try_into()
            .unwrap();

        let sec_key = unsafe {
            let mut out = MaybeUninit::<ctt_eth_bls_seckey>::uninit();
            let status = ctt_eth_bls_deserialize_seckey(out.as_mut_ptr(), raw_seckey.as_ptr());
            assert!(
                status as u8 == 0,
                "Secret key deserialization failure: {:?}",
                status
            );
            out.assume_init()
        };
        // Derive the matching public key
        let pub_key = unsafe {
            let mut out = MaybeUninit::<ctt_eth_bls_pubkey>::uninit();
            let status =
                ctt_eth_bls_derive_pubkey(out.as_mut_ptr(), &sec_key as *const ctt_eth_bls_seckey);
            assert!(
                status as u8 == 0,
                "Public key derivation failure: status: {:?}",
                status
            );
            out.assume_init()
        };

        // Sign a message
        let message = unsafe {
            let mut out = MaybeUninit::<[u8; 32]>::uninit();
            ctt_eth_bls_sha256_hash(
                out.as_mut_ptr() as *mut u8,
                "Mr F was here".as_ptr(),
                13,
                false,
            );
            // ctt_eth_bls_sha256_hash(out.as_mut_ptr(), &sec_key as *const ctt_eth_bls_seckey, )
            out.assume_init()
        };

        let sig = unsafe {
            let mut out = MaybeUninit::<ctt_eth_bls_signature>::uninit();

            let status = ctt_eth_bls_sign(
                out.as_mut_ptr(),
                &sec_key as *const ctt_eth_bls_seckey,
                message.as_ptr(),
                32,
            );
            assert!(
                status as u8 == 0,
                "Message signing failure: status {:?}",
                status
            );

            out.assume_init()
        };
        // Verify that a signature is valid for a message under the provided public key
        unsafe {
            let status = ctt_eth_bls_verify(
                &pub_key as *const ctt_eth_bls_pubkey,
                message.as_ptr(),
                32,
                &sig as *const ctt_eth_bls_signature,
            );
            assert!(
                status as u8 == 0,
                "Signature verification failure: status {:?}",
                status
            );
        }
    }
}
