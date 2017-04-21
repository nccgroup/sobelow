# Sobelow

Sobelow is a security-focused static analysis tool for the Phoenix 
framework. For security researchers, it is a useful tool for getting 
a quick view of points-of-interest. For project maintainers, it can 
be used to prevent introducing a number of common vulnerabilities. 

Currently Sobelow detects some types of the following security 
issues: 

* Insecure configuration
* Cross-Site Scripting
* SQL injection
* Directory traversal
* Unsafe serialization

Potential vulnerabilities are flagged in different colors according 
to confidence in exploitability. High confidence is red, medium 
confidence is yellow, and low confidence is green.

**Note:** This project was built to easily allow additional security 
checks. It is in constant development, and more vulnerabilities will 
be flagged as time goes on. 

If you encounter a bug, or would like to request additional features, 
please open an issue!

## Installation

To install Sobelow, you must have a working Elixir environment. Then, 
execute the following from the commandline: 

    $ mix archive.install https://github.com/GriffinMB/sobelow/raw/master/sobelow.ez
    
## Use

The simplest way to scan a Phoenix project is to run the following 
from the project root:

    $ mix sobelow

If the project is an umbrella app, or otherwise in another directory, 
the project can be scanned using the `--root` (or `-r`) flag.

    $ mix sobelow --root ../my_project

The `--with-code` (or `-v`) flag can be used to print code snippets along with 
the findings.

    $ mix sobelow --with-code
    
Modules can be ignored by passing a comma-separated list with an 
`--ignore` (or `-i`) flag.

    $ mix sobelow -i XSS,SQL
    
## Supported Modules

* XSS
* XSS.Raw
* XSS.SendResp
* SQL
* SQL.Inject
* Config
* Config.CSRF
* Config.HTTPS
* Config.Secrets
* Traversal
* Traversal.SendFile
* Traversal.FileModule
* Misc
* Misc.BinToTerm
    
This list (and other helpful information), can be also be found on 
the commandline:

    $ mix help sobelow
