# Changelog

## v0.13.0
  * Removed
    * Support for minimum Elixir versions 1.5 & 1.6 (**POTENTIALLY BREAKING** - only applies if you relied on Elixir 1.5 or 1.6, 1.7+ is still supported)
  * Enhancements
    * Fixed all `credo` warnings
    * Implemented all `credo` "Code Readability" adjustments
    * Took advantage of _some_ `credo` refactoring opportunities
    * Added (sub)module documentation that was missing for some vulnerabilities and unified presentation of others
  * Bug fixes
    * Fixed `--details` / `-d` not displaying correct information
    * Fixed incompatibility issue with Elixir 1.15
  * Misc
    * Added `mix credo --strict` to project
    * Improvements to GitHub CI
      * Hex Audit
      * Compiler Warnings as Errors
      * Checks Formatting
    * Added helper `mix test.all` alias
    
## v0.12.2
  * Bug fixes
    * Removed `:castore` and introduced `:verify_none` to quiet warning and unblock escript usage, see [#133](https://github.com/nccgroup/sobelow/issues/133) for more context on why this is necessary

## v0.12.1
  * Bug fixes
    * Lowered required version of `:castore` to remove upgrade path issues
    * Reconfigured `:verify_peer` to _actually_ use CAStore and remove warning

## v0.12.0
  * Removed
    * Support for minimum Elixir version 1.4 (**POTENTIALLY BREAKING** - only applies if you relied on Elixir 1.4, 1.5+ is still supported)
  * Enhancements
    * Adds support for HEEx to XSS.Raw
    * Adds `--version` CLI flag
    * README Improvements
      * Umbrella App usage
      * Clearer installation process
      * Layout changes
    * Updated dependencies
  * Bug fixes
    * Adds to_string() to exit_on
    * Sets SSL opt verify_peer in version check
    * Reworks `-v, --verbose` printing to not use the now deprecated `Macro.to_string/2`
  * Misc
    * Allows atom values for threshold in config file
    * Uses SPDX ID for licenses in mixfile
    * Fixed typo

## v0.11.2
  * Enhancements
    * Simplify `--flycheck` output to align with expected format

## v0.11.1
  * Enhancements
    * Sarif output with `--out` flag
    * `--strict` flag, which throws compilation errors instead of suppressing them.  

## v0.11.0
  * Enhancements
    * Sarif output for GitHub integration
    * `--flycheck` flag, which reverses output of `--compact`
  * Bug fixes
    * Non-compiling files now return an empty syntax tree instead of 
    causing Sobelow errors.
    * Command Injection finding description are properly formatted
  * Misc
    * If you use Sobelow as a standalone utility (i.e. not as part of 
    a Phoenix application), you now need to install as an escript with 
    `mix escript.install hex sobelow`.
    * Custom JSON serialization replaced with Jason.

## v0.10.6
  * Bug fixes
    * Handle nil `config` case

## v0.10.5
  * Misc
    * Update code to clean up deprecation warnings

## v0.10.4
  * Enhancements
    * Sobelow is now smarter about cross-site websocket hijacking
    * Update URL for CSRF description

## v0.10.3
  * Bug fixes
    * Fix directory structure issue in umbrella applications
    * Handle function capture edge cases

## v0.10.2
  * Bug fixes
    * Fix a format error in JSON output encoding

## v0.10.1
  * Bug fixes
    * Sobelow will use ".sobelow-skips" instead of ".sobelow" in your root directory for `--mark-skip-all`

## v0.10.0
  * Enhancements
    * Sobelow now uses "~/.sobelow/sobelow-vsn-check" for update checks
    * The ".sobelow" file in your project root is for `--mark-skip-all` only

## v0.9.3
  * Enhancements
    * Improved checks for all aliased functions
    
  * Bug Fixes
    * JSON output for Raw findings is now properly normalized
    * `send_download` correctly flags aliased function calls
    * `send_download` now correctly flags piped functions

## v0.9.2
  * Bug Fixes
    * Fix error that resulted from redefining imported functions

## v0.9.1
  * Bug Fixes
    * Revert umbrella app recursion

## v0.9.0
  * Enhancements
    * Add `--mark-skip-all` and `--clear-skip` flags
    * New CSRF via action reuse checks
    * Sobelow can now be run in umbrella apps
     
  * Bug Fixes
    * Fix an error when printing some kinds of variables

## v0.8.0
  * Enhancements
    * Improve output consistency
        * All JSON findings contain `type`, `file`, and `line` keys
        * "Line" output now refers directly to the vulnerable line
        * Default output headers have been normalized
    
    **Note:** If you depend on the structure of the output, this 
    may be a breaking change. More information can be found at 
    [https://sobelow.io](https://sobelow.io).

## v0.7.8
  * Enhancements
    * Add `--threshold` flag
    * Add module names to finding output
    
  * Deprecations
    * File/Path check has been deprecated  
   
  * Bug Fixes
    * Fix inaccurate CSRF details

## v0.7.7
  * Enhancements
    * Add check for insecure websocket settings
    
  * Bug Fixes
    * Accept module attributes for application name

## v0.7.6

  * Bug Fixes
    * Fix issue that suppressed output options when config files were in use

## v0.7.5

  * Misc
    * Sobelow will now only halt when `--exit` flag is used

## v0.7.4

  * Bug Fixes
    * Log hardcoded secrets for txt output

## v0.7.3

  * Misc
    * Tweaks to `--out` flag.

## v0.7.2

  * Enhancements
    * Add router path to config findings
    * Add `--out` flag for writing to file

## v0.7.1

  * Enhancements
    * Improved handling of JSON format
    * Additional checks for File functions

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
