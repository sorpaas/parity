#![feature(lang_items, core_intrinsics)]
#![feature(start)]
#![feature(link_args)]
#![no_std]
use core::{intrinsics, slice};

// Pull in the system libc library for what crt0.o likely requires.
extern crate libc;
extern crate tiny_keccak;
extern crate tiny_secp256k1;

use tiny_secp256k1::{is_valid_secret, create_public_key, ECPointG};

#[link_args = "-s EXPORTED_FUNCTIONS=['_verify_secret','_keccak256','_brain','_ecpointg']"]
extern {}

use tiny_keccak::Keccak;

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    #[inline]
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}

#[no_mangle]
pub fn keccak256(in_ptr: *const u8, in_len: usize, out_ptr: *mut u8) {
    let data = unsafe { slice::from_raw_parts(in_ptr, in_len) };

    let mut res = unsafe { slice::from_raw_parts_mut(out_ptr, 32) };
    let mut sha3 = Keccak::new_keccak256();

    sha3.update(data);
    sha3.finalize(res);
}

#[no_mangle]
pub fn ecpointg(g: *mut ECPointG) {
    unsafe {
        *g = ECPointG::new();
    }
}

#[no_mangle]
pub fn verify_secret(secret: *const u8) -> bool {
    // let secret = unsafe { slice::from_raw_parts(secret, 32) };

    // is_valid_secret(secret)
    true
}

#[no_mangle]
pub fn brain(
    g: *const ECPointG,
    in_ptr: *const u8, in_len: usize,
    secret: *mut u8,
    public: *mut u8,
    address: *mut u8
) {
    let data = unsafe { slice::from_raw_parts(in_ptr, in_len) };
    let g = unsafe { &*g };

    let mut secret_out = unsafe { slice::from_raw_parts_mut(secret, 32) };
    let mut public_out = unsafe { slice::from_raw_parts_mut(public, 64) };
    let mut address_out = unsafe { slice::from_raw_parts_mut(address, 20) };

    let mut secret = data.keccak256();

    let mut i = 0;
    loop {
        secret = secret.keccak256();

        match i > 16384 {
            false => i += 1,
            true => {
                if let Some(public) = create_public_key(g, &secret) {
                    let public = &public[1..];
                    let hash = public.keccak256();

                    address_out.copy_from_slice(&hash[12..]);

                    if address_out[0] == 0 {
                        public_out.copy_from_slice(&public);
                        secret_out.copy_from_slice(&secret);
                        return;
                    }
                }
            }
        }
    }
}

// Entry point for this program.
#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    0
}

// These functions are used by the compiler, but not
// for a bare-bones hello world. These are normally
// provided by libstd.
#[lang = "eh_personality"]
#[no_mangle]
pub extern fn rust_eh_personality() {
}

// This function may be needed based on the compilation target.
#[lang = "eh_unwind_resume"]
#[no_mangle]
pub extern fn rust_eh_unwind_resume() {
}

#[lang = "panic_fmt"]
#[no_mangle]
pub extern fn rust_begin_panic(_msg: core::fmt::Arguments,
                               _file: &'static str,
                               _line: u32) -> ! {
    unsafe { intrinsics::abort() }
}
