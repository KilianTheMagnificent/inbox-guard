# inbox-guard

## Verify

Run `npm test` from the repository root. Then run the piped redaction example in the README from a clean copy. Check that the invoice number and punctuation survive and that the address becomes a single email token.

For CSV changes, follow the [verification guide](docs/checking-a-change.md) from a fresh temporary copy. Compare the original and cleaned cells and confirm that an existing destination survives a second run.
