# Changelog

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