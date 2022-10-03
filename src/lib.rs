//! OTP implementations based on [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) for Hmac-based OTPs
//! and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) for Time-based OTPs.
//!
//! **By default all features are enabled**, if you wish only to use the default functionality
//! (no `encoding`, `custom` or `qr` modules), use the flag `default-features = false`
//!
//! This module by itself allows you to generate and verify TOTPs and HOTPs using the default
//! algorithm SHA-1, the default digit length of 6 and the default time step of 30 for TOTPs.
//!
//! *The following applies only if you set `default-features = false`, by default it is included*:
//!
//! If you need finer controls over password generation and verification use the `custom_otp` feature flag
//! to gain access to the [custom] module.
//!
//! The `encoding` feature flag gives access to the [encoding] module which provides 2 basic functions to encode
//! and decode the generated keys to an encoding of choice avilable from the [data_encoding](https://docs.rs/data-encoding/latest/data_encoding/index.html) crate.
//!
//! The `qr` feature flag gives access to the [qr] module and enables QR code generation of the
//! generated secret keys ready to be used by authenticator apps.
//!
//! ## Example usage
//!
//! *Generate a secret and qr code, and verify a password generated with said secret:*
//!
//! ```
//! use thotp::{
//!     otp,
//!     verify_totp,
//!     generate_secret,
//!     encoding::{encode, decode},
//!     qr,
//! };
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! // The default time step used by this module internally
//! const TIME_STEP: u8 = 30;
//!
//! // Generate an encoded secret
//!
//! let secret = generate_secret(80);
//!
//! // The data_encoding crate is re-exported for convenience
//! let encoded = encode(&secret, data_encoding::BASE32);
//!  
//! // ...store the secret somewhere safe...
//!
//! let uri = qr::otp_uri(
//!     // Type of otp
//!     "totp",
//!     // The encoded secret
//!     &encoded,
//!     // Your big corp title
//!     "Big Corp:john.doe@email.com",
//!     // Your big corp issuer
//!     "Big Corp",
//!     // We are generating a TOTP so we don't need a counter value
//!     None,
//! ).expect("yikes");
//!
//! let qr_code = qr::generate_code_svg(
//!     &uri,
//!     // The qr code width (None defaults to 200)
//!     None,
//!     // The qr code height (None defaults to 200)
//!     None,
//!     // Correction level, M is the default
//!     qrcode::EcLevel::M,
//! )
//! .expect("uh oh");
//!
//! // ..scan the qr code with an authenticator app...
//!
//! // Verify a password provided from the client
//!
//! // When generating an OTP we have to calculate the current time slice. This is necessary
//! // upfront only when generating an otp since this function is blind to the OTP type.
//! let time_step_now = SystemTime::now()
//!      .duration_since(UNIX_EPOCH)
//!      .unwrap()
//!      .as_secs()
//!      / TIME_STEP as u64;
//!
//! // Let us assume this comes from the client
//! let pw = otp(&secret, time_step_now).unwrap();
//!
//! // The verify function calculates the current slice internally
//! let (result, discrepancy) = verify_totp(&pw, &secret, 0).unwrap();
//!
//! assert_eq!((true, 0),(result, discrepancy));
//!
//! ```
//!
//! ### A way to quickly test your QR with an authenticator
//!
//! *The following are copy pasteable functions for rapid testing with authenticator apps*
//!
//! Use the following function to generate and encode a secret and create a qr code. Uncomment the 2 write lines
//! to write the secret to a file called `temp_secret` and the qr code string to the file `qr.html`.
//!
//! ```rust
//! fn generate_code() {
//!     let secret = thotp::generate_secret(80);
//!     let secret = &thotp::encoding::encode(&secret, data_encoding::BASE32);
//!     
//!     let uri = thotp::qr::otp_uri("totp", &secret, "THOTP:test@email.com", "THOTP", None).unwrap();
//!
//!     let code = thotp::qr::generate_code_svg(
//!         &uri,
//!         Some(300),
//!         Some(300),
//!         thotp::qr::EcLevel::H,
//!     )
//!     .unwrap();
//!
//!     // Uncomment these lines to write the temporary files
//!
//!     // std::fs::write("./temp_secret", secret).unwrap();
//!     // std::fs::write("./qr.html", code).unwrap();
//! }
//! ```
//!
//! Load the html file in your browser and scan it with an authenticator app.
//! The `temp_secret` file is used to temporarily hold the secret for the generated
//! qr code. Once you've loaded the code to the app, you can use the following
//! function to print out an TOTP generated with the default parameters (SHA1, 6 digits, Time step = 30).
//!
//! ```rust,ignore
//! fn print_pw_totp(secret: &str /*use the string from the temp_secret file */) {
//!     let secret = decode(secret, data_encoding::BASE32).unwrap();
//!     let nonce = std::time::SystemTime::now()
//!         .duration_since(std::time::UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs()
//!         / TIME_STEP as u64;
//!     let totp = otp(&secret, nonce).unwrap();
//!     println!("TOTP: {}", totp);
//! }
//! ```
//!
//! To test HOTPs, simply replace the "totp" parameter with "hotp" and use the following function:
//! ```rust,ignore
//! fn print_pw_hotp(secret: &str /*use the string from the temp_secret file */, counter: u64) -> Result<(), ThotpError> {
//!     let secret = decode(secret, data_encoding::BASE32).unwrap();
//!     let hotp = otp(&secret, counter).unwrap();
//!     println!("HOTP: {}", hotp);
//! }
//! ```
//!
//! There are 3 constants used by this module internally;
//!
//! The `DIGITS_DEFAULT` constant is the default password length generated by the `otp` function as well
//! as when verifying and is equal to 6.
//!
//! The `TIME_STEP` is the default and RFC recommended time step used to divide the duration in seconds from now
//! until the unix epoch and is equal to 30.
//!
//! When TOTPs are generated, there is a chance they will be generated at the end of a time step and by
//! the time they reach the server the password would be invalid because it would fall in the previous
//! time step. This is mitigated by allowing passwords from `ALLOWED_DRIFT` time steps prior and subsequent
//! to the current to be valid. The value of this is the RFC recommended amount 1, meaning the passwords from the time slice
//! prior and subsequent to the current one are considered valid.
//!
//! The same drift can happen with HOTPs with the counter, and a lookahead parameter can be used to adjust
//! how many passwords will be considered valid from the current counter.
//!
//! #### A note on key length
//!
//! The [GA wiki](https://en.wikipedia.org/wiki/Google_Authenticator) says that a secret of 80 bits is required,
//! however keys with longer buffer sizes (160 specifically) were succesfully registered and were giving correct
//! passwords, so there is a chance the wikipedia page is deprecated. The RFC recommended key length is 160
//! so it is advised you stick to 160 for the secret length for the recommended security if it works.
//! *The length refers to the buffer size for the `generate_secret` function, NOT the Base32 encoded version of it.*

#![crate_type = "lib"]

mod otp_core;

#[cfg(feature = "custom")]
pub mod custom;

#[cfg(feature = "encoding")]
pub mod encoding;

#[cfg(feature = "qr")]
pub mod qr;

use otp_core::{
    dynamic_trunc, hmac_digest, time_step_now, ALLOWED_DRIFT, DIGITS_DEFAULT, TIME_STEP,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Uses HMAC-SHA-1 and the default digit length of 6 to generate a one time password.
///
/// The security of the OTP generated by this function is as recommended by the RFC and should be
/// adequate for most intents and purposes. If you need finer control over how the
/// inputs are hashed or the digit length, use the `custom_otp` feature flag which provides functions with
/// more customizable parameters.
///
/// The `secret` is an arbitrary byte array (one can be generated with this crate's `generate_secret` function)
/// and the `nonce` is either a unix timestamp divided by the time step when dealing with TOTPs
///  or a counter when dealing with HOTPs.
///
/// The default verification functions use this function to create a password to compare to their inputs.
pub fn otp(secret: &[u8], nonce: u64) -> Result<String, ThotpError> {
    // Transform to bytes
    let nonce = &nonce.to_be_bytes();

    // Create an HMAC digest with the given key, nonce and algorithm
    let mut hmac = hmac_digest::<Sha1>(secret, nonce)?;

    // Truncate to 4 bytes
    let trunc = dynamic_trunc(&mut hmac);

    // Mod it with the default number of digits to get the password
    let mut result = (trunc % 10_u32.pow(DIGITS_DEFAULT as u32)).to_string();

    // Pad with 0s if the number is shorter than the necessary digits
    for i in 0..(DIGITS_DEFAULT as usize - result.len() as usize) {
        result.insert(i, '0');
    }

    Ok(result)
}

/// Verifies the given password for the given timestamp and secret.
///
/// Uses SHA1, the default digit length of 6 and the default time step of 30
/// to generate a password to compare with the given one. If you need finer control
/// of the verification parameters, use the `custom_otp` feature flag.
///
/// The function considers passwords from the previous and next `ALLOWED_DRIFT` time slices
/// to be valid.
///
/// The function returns a tuple whose first element is a boolean indicating whether any
/// of the passwords in the allowed drift match and the second element is a number
/// indicating the number of time slices the valid password deviates from the current
/// time slice. In this function the only possible values for the discrepancy are -1 (indicating the password from
/// the slice prior is valid), 0 (indicating the current one is valid) and 1 (indicating the password from
/// the next time slice is valid) since it will only look at the previous and next time slice in
/// addition to the current one.
///
/// If a `timestamp` of 0 is provided, the current system time will be used for the calculation.
///
/// ## Example
/// ```
/// use thotp::{otp, generate_secret, verify_totp};
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// const TIME_STEP: u8 = 30;
///
/// let secret = generate_secret(420);
///
/// let time_step_now = SystemTime::now()
///      .duration_since(UNIX_EPOCH)
///      .unwrap()
///      .as_secs()
///      / TIME_STEP as u64;
///
/// let pw = otp(&secret, time_step_now).unwrap();
///
/// let (result, discrepancy) = verify_totp(&pw, &secret, 0).unwrap();
///
/// assert_eq!((true, 0),(result, discrepancy));
///
/// ```
pub fn verify_totp(
    password: &str,
    secret: &[u8],
    timestamp: u64,
) -> Result<(bool, i16), ThotpError> {
    let nonce = if timestamp == 0 {
        time_step_now()?
    } else {
        timestamp / TIME_STEP as u64
    };

    let start = nonce.saturating_sub(ALLOWED_DRIFT as u64);
    let end = nonce.saturating_add(ALLOWED_DRIFT as u64);

    // Keeps track of how large the deicrepancy is
    let mut i = -(ALLOWED_DRIFT as i16);

    for n in start..=end {
        let pass = otp(secret, n)?;
        if pass.eq(password) {
            return Ok((true, i));
        }
        i += 1;
    }

    Ok((false, 0))
}

/// Generates multiple hotp passwords in the range of `lookahead + 1` and compares them to the input.
/// The counter wraps around on overflow.
/// A lookahead of 0 means only the current counter will be used in the verification.
///
/// Uses SHA1 and the default digit length of 6.
/// If you need finer control of the verification parameters, use the `custom_otp` feature flag.
///
/// If verification is successful the counter is incremented, otherwise it is left as is.
///
/// ## Example
/// ```
/// use thotp::{otp, verify_hotp};
///
/// let counter = 1;
/// let secret = b"super secret";
/// let password = otp(secret, counter).unwrap();
///
/// let (result, counter) = verify_hotp(&password, secret, counter, 0).unwrap();
///
/// assert_eq!(counter, 2);
/// assert!(result);
///
/// let (result, counter) = verify_hotp("fail", secret, counter, 0).unwrap();
///
/// assert_eq!(counter, 2);
/// assert!(!result);
/// ```
pub fn verify_hotp(
    password: &str,
    secret: &[u8],
    counter: u64,
    lookahead: usize,
) -> Result<(bool, u64), ThotpError> {
    for current in 0..lookahead + 1 {
        let curr = (counter as u128 + current as u128) as u64;

        let pass = otp(secret, curr)?;

        if pass.eq(password) {
            return Ok((true, (curr as u128 + 1) as u64));
        }
    }

    Ok((false, counter))
}

/// Generates a secret key, i.e. a buffer filled with random bytes. The RFC recommended buffer
/// size is 160.
///
/// ## Example
/// ```
/// use thotp::generate_secret;
/// use thotp::encoding::encode;
///
/// let secret = generate_secret(420);
///
/// assert_eq!(secret.len(), 420);
///
/// let encoded = encode(&secret, data_encoding::BASE32);
///
/// // Store it or generate a qr code...
///
/// ```
pub fn generate_secret(size: usize) -> Vec<u8> {
    let mut key = vec![0; size];

    let mut rng = StdRng::from_entropy();

    rng.fill_bytes(&mut key);

    key
}

/// A wrapper around all the possible errors that can be encountered when using this module.
/// When generating OTPs an error may occur if an invalid length is provided to the Hmac hasher
/// as well as when calculating the system time so we have to take it in to account and handle it
/// properly. Additional errors are covered when using the `custom`, `qr` or `decoding` modules.
#[derive(Error, Debug)]
pub enum ThotpError {
    #[error("Invalid buffer length provided for Hmac: `{0}`")]
    InvalidLength(#[from] digest::InvalidLength),

    #[error("Invalid digits provided, the minimum is 6 and the maximum is 10")]
    InvalidDigits,

    #[error("{0}")]
    InvalidUri(String),

    #[error("An error occurred while trying to calculate system time: `{0}`")]
    SystemTime(#[from] std::time::SystemTimeError),

    #[cfg(feature = "encoding")]
    #[error("An error occurred while trying to decode string: `{0}`")]
    Encoding(#[from] data_encoding::DecodeError),

    #[cfg(feature = "qr")]
    #[error("An error occurred while generating QR code: `{0}`")]
    QR(#[from] qrcode::types::QrError),

    #[cfg(feature = "qr")]
    #[error("Formatting error: {0}")]
    Format(#[from] std::fmt::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom::*;

    const TEST_KEY: &[u8; 20] = b"12345678901234567890";

    #[test]
    fn hotp_generation_verification() -> Result<(), ThotpError> {
        let counter = 1;
        let password = otp(TEST_KEY, counter)?;
        let (result, counter) = verify_hotp(&password, TEST_KEY, counter, 0)?;
        assert_eq!(counter, 2);
        assert_eq!(result, true);

        let password = otp_custom::<Sha1>(TEST_KEY, counter, DIGITS_DEFAULT)?;
        let (result, counter) = verify_hotp(&password, TEST_KEY, counter, 0)?;
        assert_eq!(counter, 3);
        assert_eq!(result, true);

        let (result, counter) = verify_hotp("fail", TEST_KEY, counter, 0)?;
        assert_eq!(result, false);
        assert_eq!(counter, 3);

        // Test with lookahead and overflow
        let password = otp_custom::<Sha1>(TEST_KEY, counter, DIGITS_DEFAULT)?;
        let (result, counter) = verify_hotp(&password, TEST_KEY, u64::MAX, 20)?;
        assert_eq!(result, true);
        assert_eq!(counter, 4);

        let password = otp_custom::<Sha1>(TEST_KEY, u64::MAX - 1, DIGITS_DEFAULT)?;
        let (result, counter) = verify_hotp(&password, TEST_KEY, u64::MAX - 18, 20)?;
        assert_eq!(result, true);
        assert_eq!(counter, u64::MAX);

        // Sha1
        let password = otp_custom::<Sha1>(TEST_KEY, counter, DIGITS_DEFAULT)?;
        let (result, counter) = verify_hotp(&password, TEST_KEY, u64::MAX, 0)?;
        assert_eq!(result, true);
        assert_eq!(counter, 0);

        // Sha256
        let password = otp_custom::<Sha256>(TEST_KEY, u64::MAX - 1, DIGITS_DEFAULT)?;
        let (result, counter) =
            verify_hotp_custom::<Sha256>(&password, TEST_KEY, u64::MAX - 18, 20, DIGITS_DEFAULT)?;
        assert_eq!(result, true);
        assert_eq!(counter, u64::MAX);

        // Sha512
        let password = otp_custom::<Sha512>(TEST_KEY, u64::MAX - 1, DIGITS_DEFAULT)?;
        let (result, counter) =
            verify_hotp_custom::<Sha512>(&password, TEST_KEY, u64::MAX - 18, 20, DIGITS_DEFAULT)?;
        assert_eq!(result, true);
        assert_eq!(counter, u64::MAX);

        Ok(())
    }

    // The values in the next 3 tests come from the RFC
    #[test]
    fn totp_sha1() {
        let secret: &[u8] = b"12345678901234567890";
        assert_eq!(20, secret.len());

        let pairs = vec![
            ("94287082", 59),
            ("07081804", 1111111109),
            ("14050471", 1111111111),
            ("89005924", 1234567890),
            ("69279037", 2000000000),
            ("65353130", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, timestamp)| {
            assert_eq!(
                expected,
                otp_custom::<Sha1>(secret, timestamp / TIME_STEP as u64, 8).unwrap()
            );
            assert_eq!(
                (true, 0),
                verify_totp_custom::<Sha1>(expected, secret, timestamp, 8, TIME_STEP, 1).unwrap()
            );
        });
    }
    #[test]
    fn totp_sha256() {
        let secret: &[u8] = b"12345678901234567890123456789012";
        assert_eq!(32, secret.len());

        let pairs = vec![
            ("46119246", 59),
            ("68084774", 1111111109),
            ("67062674", 1111111111),
            ("91819424", 1234567890),
            ("90698825", 2000000000),
            ("77737706", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, timestamp)| {
            assert_eq!(
                expected,
                otp_custom::<Sha256>(secret, timestamp / TIME_STEP as u64, 8).unwrap()
            );
            assert_eq!(
                (true, 0),
                verify_totp_custom::<Sha256>(expected, secret, timestamp, 8, TIME_STEP, 1).unwrap()
            );
        });
    }
    #[test]
    fn totp_sha512() {
        let secret: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(64, secret.len());

        let pairs = vec![
            ("90693936", 59),
            ("25091201", 1111111109),
            ("99943326", 1111111111),
            ("93441116", 1234567890),
            ("38618901", 2000000000),
            ("47863826", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, timestamp)| {
            assert_eq!(
                expected,
                otp_custom::<Sha512>(secret, timestamp / TIME_STEP as u64, 8).unwrap()
            );
            assert_eq!(
                (true, 0),
                verify_totp_custom::<Sha512>(expected, secret, timestamp, 8, TIME_STEP, 1).unwrap()
            );
        });
    }
}
