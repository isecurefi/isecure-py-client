# Inline UploadFile response review — 2026-10-23

## Pass 1: response preservation and compatibility

Previously upload_file checked HTTP status then discarded the response body and
returned None. It now returns the JSON object, including optional raw Base64
Content. Acknowledgements without Content remain unchanged dictionaries. Existing
callers ignoring the return value continue working; callers explicitly expecting
None must adapt. Non-object response bodies raise ValueError instead of violating
the declared dictionary return type. HTTP failures retain existing handling.

## Pass 2: request integrity and diagnostics

Ten new regression cases check inline, empty and absent Content with and without
signatures, exact signed upload contents, one PUT, HTTP refusal, and malformed
non-object bodies. Success paths do not log the upload or returned Content. The
new code neither decodes reports nor downloads another file. It adds no bank- or
simulator-specific logic. The existing three PGP tests also pass.

## Pass 3: package and live verification

Python 3.12 checks pass: Ruff, mypy, all 13 tests, source/wheel builds and pip check.
A separate virtual environment installed the built wheel, authenticated to
gpgtest, and uploaded a signed camt.060 query. The returned Content decoded with
strict Base64 to an XSD-valid camt.052 report containing the same account and
balances as the TypeScript SDK and prepared C# NuGet package. File lists before
and after the Python upload matched; the shared inventory stayed unchanged across
all three clients. This qualifies this specific login/inline-query flow only.

Guarded cleanup suspended the retained synthetic tenant entitlement and confirmed
readback; accounts and audit streams were retained. Cache-expiry denial is recorded
in the private shared evidence. No production bank operation was performed.

Private evidence is under the C# repository's `.private/inline-upload-evidence-20261023/`
and the Python repository's corresponding directory. It contains credentials and
must not be published. Existing PGP warnings and packaging/configuration deprecation
warnings remain; no test failures or type/lint errors remain. No package or API
documentation was published, and the preparation retains the current package version.
