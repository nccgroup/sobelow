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

## Installation

To install Sobelow, you must have a working Elixir environment. Then, 
execute the following from the commandline: 

    $ mix archive.install <TODO_ADD_LINK>
    
## Use

The simplest way to scan a Phoenix project is to run the following 
from the project root:

    $ mix sobelow

### Root
If the project is an umbrella app, or otherwise in another directory, 
the project can be scanned using the `root` flag.

    $ mix sobelow --root ../my_project
    
Or

    $ mix sobelow -r ../my_project

### With Code
The `with-code` flag can be used to print code snippets along with 
the findings.

    $ mix sobelow --with-code
    
Or

    $ mix sobelow -v
    
### Ignore
Modules can be ignored by passing a comma-separated list with an 
`-i` or `--ignore` flag.

    $ mix sobelow -i XSS,SQL
    
A complete list of ignorable modules can be found using the following 
command:

    $ mix help sobelow
