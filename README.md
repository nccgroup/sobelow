# Sobelow

This project is in development, and not ready for use. Currently `sobelow` can flag 
XSS with varying levels of confidence, some configuration issues, and some instances 
of potential SQL injection.

Findings are color-coded based on the level of confidence in exploitability. 
High confidence findings are red, medium confidence are yellow, and low confidence are 
green.

The initial release will attempt to detect the following:

* Configuration issues
* Cross-Site Scripting
* SQL Injection
* Directory Traversal
* Code Execution

