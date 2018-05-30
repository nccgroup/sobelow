# Changelog

## v0.7.0

  * Enhancements
    * Improved handling of vulnerabilities within templates.

  * Bug Fixes
    * Sobelow no longer incorrectly flags :binary `send_download` functions.

## v0.6.9

  * Enhancements
    * Improve template parsing and validation.
    * Support multiple routers, and improve route discovery.

  * Misc.
    * Update language for missing directory.

## v0.6.8

  * Bug Fixes
    * Fix bug in the handling of certain piped functions.
    * Revert not/in update that broke Elixir 1.4 compatibility.

## v0.6.7

  * Enhancements
    * Remove banner print from JSON format.

  * Bug Fixes
    * Fix error that occurred with certain function names in JSON format.

## v0.6.6

  * Enhancements
    * Add check for directory traversal via `send_download`
    * Add check for missing Content-Security-Policy
    * Check additional XSS vectors

## v0.6.5

  * Bug Fixes
    * Allow RCE module to be appropriately ignored.
    
## v0.6.4

  * Enhancements
    * Set timeout for version check.

## v0.6.3

  * Enhancements
    * Add RCE module to check for code execution via `Code` and `EEx`.
    
  * Deprecations
    * The `--with-code` flag has been changed to `--verbose`. The `--with-code` 
    flag will continue to work as expected until v1.0.0, but will print a 
    warning message.
