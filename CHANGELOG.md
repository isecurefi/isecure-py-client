# Changelog

## 0.1.1 — 2026-10-23

- Return the bank response dictionary from `upload_file`, preserving optional inline Base64 `Content`.
- Keep HTTP refusal handling and exact upload bytes/signatures unchanged.
- Add inline-response regression tests and qualify a separately installed wheel against gpgtest.

The SDK remains Beta. Calls that ignore the return value continue working; code
explicitly expecting `None` should use the returned dictionary instead.
