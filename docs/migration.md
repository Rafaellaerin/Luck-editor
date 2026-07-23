# Migrating to Luck Editor 5

## Procedure

1. Export only the cookies you need from the previous version.
2. Review the file and remove any unnecessary credentials.
3. Remove the old extension from the browser.
4. Run `npm run verify`.
5. Load `dist/extension` as an unpacked extension.
6. Open the target website and import the file.
7. Review all errors and warnings before confirming.
8. Delete the export file when it is no longer needed.

## Intentional Incompatibilities

* Old snapshots are not imported automatically.
* Access to all websites is no longer permanent.
* Invalid entries are no longer accepted silently.
* `SameSite=None` without `Secure` is rejected.
* Domains outside the active host are rejected by the extension.
* `HttpOnly` export is disabled by default.
* Values are masked, and snapshots are redacted by default.
