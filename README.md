# Sobelow

Sobelow is a security-focused static analysis tool for the 
Phoenix framework. For security researchers, it is a useful 
tool for getting a quick view of points-of-interest. For 
project maintainers, it can be used to prevent the introduction 
of a number of common vulnerabilities. 

Currently Sobelow detects some types of the following 
security issues: 

* Insecure configuration
* Known-vulnerable Dependencies
* Cross-Site Scripting
* SQL injection
* Command injection
* Denial of Service
* Directory traversal
* Unsafe serialization

Potential vulnerabilities are flagged in different colors 
according to confidence in their insecurity. High confidence is 
red, medium confidence is yellow, and low confidence is green.

A finding is typically marked "low confidence" if it looks 
like a function could be used insecurely, but it cannot 
reliably be determined if the function accepts user-supplied 
input. That is to say, if a finding is marked green, it may be 
critically insecure, but it will require greater manual 
validation. 

**Note:** This project is in constant development, and 
additional vulnerabilities will be flagged as time goes on. 
If you encounter a bug, or would like to request additional 
features or security checks, please open an issue!

## Installation

To install Sobelow, you must have a working Elixir environment. 
Then, execute the following from the command line: 

    $ mix archive.install hex sobelow

You may also install directly from GitHub with the following 
command:

    $ mix archive.install github nccgroup/sobelow
    
## Use

The simplest way to scan a Phoenix project is to run the 
following from the project root:

    $ mix sobelow

## Options

  * `--root -r` - Specify application root directory
  * `--verbose -v` - Print code snippets and additional finding details
  * `--ignore -i` - Ignore modules
  * `--ignore-files` - Ignore files
  * `--details -d` - Get module details
  * `--all-details` - Get all module details
  * `--private` - Skip update checks
  * `--router` - Specify router location
  * `--exit` - Return non-zero exit status
  * `--format -f` - Specify findings output format
  * `--quiet` - Return no output if there are no findings
  * `--compact` - Minimal, single-line findings  
  
The `root` option takes a path argument:

    $ mix sobelow --root ../my_project

The `verbose` option takes no arguments:

    $ mix sobelow --verbose
    
The `ignore` option takes a comma-separated list of modules:

    $ mix sobelow -i XSS.Raw,Traversal
    
The `ignore-files` option takes a comma-separated list of file 
names. File names should be absolute paths, or relative to the 
application root.

    $ mix sobelow --ignore-files config/prod.exs
    
The `details` option takes a single module:

    $ mix sobelow -d Config.CSRF
    
The `exit` option accepts a confidence threshold (low, medium, or high), 
and will return a non-zero exit status at or above that threshold.

    $ mix sobelow --exit Low
    
The `format` option accepts an output format for findings. Current formats 
include `txt` (the default) and `json`. 

Note: The `json` format option does not support the `--verbose` flag. 
All findings are organized by confidence level, and contain a "type" 
key. However, other keys may vary between finding types.

    $ mix sobelow --format json
    
## Configuration Files
Sobelow allows users to save frequently used options in a 
configuration file. For example, if you find yourself constantly 
running:

    $ mix sobelow -i XSS.Raw,Traversal --verbose --exit Low
    
You can use the `--save-config` flag to create your `.sobelow-conf` 
config file:

    $ mix sobelow -i XSS.Raw,Traversal --verbose --exit Low --save-config
     
This command will create the `.sobelow-conf` file at the root 
of your application. You can edit this file directly to make 
changes.

You can also run the command without any options:

    $ mix sobelow --save-config

when you first start out using this package - the generated configuration file
will be populated with the default values for each option. (This helps in
quickly incorporating this package into a pre-existing codebase.)

Now if you want to run Sobelow with the saved configuration,
you can run Sobelow with the `--config` flag.

    $ mix sobelow --config

## False Positives
Sobelow favors over-reporting versus under-reporting. As such, 
you may find a number of false positives in a typical scan. 
These findings may be individually ignored by adding a 
`# sobelow_skip` comment, along with a list of modules, before 
the function definition. 

```elixir
# sobelow_skip ["Traversal"]
def vuln_func(...) do
  ...
end
```

Then, run the scan with the `--skip` flag.

    $ mix sobelow --skip

Config and Vulnerable Dependency findings cannot be skipped in 
this way. For these, use the standard `ignore` option.

## Modules
Findings categories are broken up into modules. These modules 
can then be used to either ignore classes of findings (via the 
`ignore` and `skip` options) or to get vulnerability details (via the 
`details` option).
 
This list, and other helpful information, can be found on the 
command line:

    $ mix help sobelow

## Updates
When scanning a project, Sobelow will occasionally check for 
updates, and will print an alert if a new version is available. 
Sobelow keeps track of the last update-check by creating a 
`.sobelow` file in the root of the scanned project.

If this functionality is not desired, the `--private` flag can 
be used with the scan.

    $ mix sobelow --private
