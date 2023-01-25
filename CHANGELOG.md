# Changelog

All notable changes will be documented in this file.

## [0.1.11] - 2022/11/02

### Changed

- Updated README and moved QR example to front page, fixed some docs and added more.

## [0.1.1] - 2022/10/02

### Added

- Example of how to test the generated QR code
- A function to append parameters to OTP uris `uri_append_params`

### Changed

- Rename the `generate_code` function from the qr module to `generate_code_svg` to be more explicit
- Make the `otp_uri` function public
- Generate code now takes in a uri parameter instead of everything necessary to generate a uri

### Fixed

- QR code width and height now default to 200 instead of 0

## [0.1.0] - 2022/10/02

### Initial commit

- OTP core functionality
- HOTP verification
- TOTP verification
- Encoding and decoding secret buffers
- QR code generation for authenticators
