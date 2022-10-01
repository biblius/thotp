//! Contains functions providing finer control over OTP generation and verification parameters

use super::*;
use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    FixedOutput, HashMarker, Update,
};

// Re-export the hashing algorithms
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

/// Generates a one time password using the given secret, nonce, digits and algorithm.
pub fn otp_custom<H>(secret: &[u8], nonce: u64, digits: u8) -> String
where
    H: Update + FixedOutput + CoreProxy,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    // Transform to bytes
    let nonce = &nonce.to_be_bytes();

    // Create an HMAC digest with the given key, nonce and algorithm
    let mut hmac = hmac_digest::<H>(secret, nonce);

    // Truncate to 4 bytes
    let trunc = dynamic_trunc(&mut hmac);

    // Mod it with the number of digits for the password
    let mut result = (trunc % 10_u32.pow(digits as u32)).to_string();

    // Pad with 0s if the number is shorter than the necessary digits
    for i in 0..(digits as usize - result.len() as usize) {
        result.insert(i, '0');
    }

    result
}

/// Verifies the given password for the given timestamp and secret.
///
/// Uses the provided algorithm, digit length and time step
/// to generate a password to compare with the given one. If a `timestamp` of 0
/// is provided, the current system time will be used for the calculation.
/// ## Example
/// ```
/// // An example from RFC 6238 with SHA1
/// use thotp::custom::{otp_custom, verify_totp_custom};
/// use thotp::custom::Sha1;
/// use thotp::{TIME_STEP, ALLOWED_DRIFT};
///
/// let secret = b"12345678901234567890";
///
/// let pairs = vec![
///     ("94287082", 59),
///     ("07081804", 1111111109),
///     ("14050471", 1111111111),
///     ("89005924", 1234567890),
///     ("69279037", 2000000000),
///     ("65353130", 20000000000),
/// ];
///
/// pairs.into_iter().for_each(|(expected, timestamp)| {
///     // When generating a totp the current unix time is divided by the time setp
///     assert_eq!(
///         expected,
///         otp_custom::<Sha1>(secret, timestamp / TIME_STEP as u64, 8)
///     );
///
///     // The verify function does this internally
///     assert!(verify_totp_custom::<Sha1>(
///         expected, secret, timestamp, 8, TIME_STEP, ALLOWED_DRIFT
///     ));
/// });
/// ```
pub fn verify_totp_custom<H>(
    password: &str,
    secret: &[u8],
    timestamp: u64,
    digits: u8,
    step: u8,
    allowed_drift: u8,
) -> bool
where
    H: Update + FixedOutput + CoreProxy,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let nonce = if timestamp == 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / step as u64
    } else {
        timestamp / step as u64
    };

    let start = nonce.saturating_sub(allowed_drift as u64);
    let end = nonce.saturating_add(allowed_drift as u64);

    for n in start..=end {
        let pass = otp_custom::<H>(secret, n, digits);

        if pass.eq(password) {
            return true;
        }
    }

    false
}

/// Uses the provided algorithm, digit length and lookahead to generate `lookahead + 1` passwords
/// to compare with the given one.
///
/// If verification is successful the counter is incremented, otherwise it is left as is.
///
/// ## Example
/// ```
/// use thotp::custom::{otp_custom, verify_hotp_custom};
/// use thotp::custom::Sha256;
/// use thotp::DIGITS_DEFAULT;
///
/// let key = b"super secret";
/// let password = otp_custom::<Sha256>(key, u64::MAX - 1, DIGITS_DEFAULT);
///
/// let (result, counter) = verify_hotp_custom::<Sha256>(&password, key, u64::MAX - 18, 20, DIGITS_DEFAULT);
///
/// assert_eq!(result, true);
/// assert_eq!(counter, u64::MAX);
/// ```
pub fn verify_hotp_custom<H>(
    password: &str,
    secret: &[u8],
    counter: u64,
    lookahead: u8,
    digits: u8,
) -> (bool, u64)
where
    H: Update + FixedOutput + CoreProxy,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    for current in 0..lookahead + 1 {
        let current = (counter as u128 + current as u128) as u64;

        let pass = otp_custom::<H>(secret, current, digits);

        if pass.eq(password) {
            return (true, (current as u128 + 1) as u64);
        }
    }

    (false, counter)
}
