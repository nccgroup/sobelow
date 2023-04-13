# Sobelow Findings Guide

When Sobelow reports a finding for an Elixir application, there are three key questions the developer should ask:

1. Is this finding a true positive or false positive? 

2. What is the security impact of the vulnerability?

3. What is the correct method to fix the vulnerability?

Sobelow is a useful tool, able to analyze the details of a code base much faster than a human. However, it only has access to source code. Sobelow does not understand how the application is being used, and the true security impact of each reported finding. The expertise of a human is required to use Sobelow effectively. 

This document provides guidelines for evaluating each possible Sobelow finding. The severity ranking for each finding is subject to debate, and ultimately up to the judgement of the application owner. Guidelines on severity are still useful, for example consider a banking application where Sobelow reports two findings:

1. `Misc.BinToTerm`, Severity: High
2. `DOS.StringToAtom`, Severity: Medium

Both these findings are a true positive. The `Misc.BinToTerm` finding means the application may be vulnerable to remote code execution, where an attacker could gain the equivalent of production SSH access to the web server. From this foothold, the attacker can issue financial transaction, modify customer records, and further compromise the banking infrastructure. Contract this finding to the `DOS.StringToAtom` finding. An attacker can use this vulnerability to crash the banking server. This is not ideal, and is a security issue, however the attacker cannot forge financial transaction or access customer data, so the severity is lower. 

## Severity Ratings

There are three possible severity ratings for each finding:

1. High

2. Medium 

3. Low

Note that these ratings are meant as a guideline, and the true impact of each vulnerability is dependent on how the application is being used. For example, a cross site scripting (XSS) issue, where the payload can only be viewed by the user who submitted it, would be classified as low. A XSS issues in a social media website would be high, because many people can view the payload, and it can lead to a worm attack, where each person who views the payload spreads it to their friends. See the [MySpace Samy worm](https://en.wikipedia.org/wiki/Samy_(computer_worm)) for a real world example. 

Given the above context, XSS is classified as high severity in these guidelines. 


## UID 1, CI.OS: Command Injection in `:os.cmd`

Command Injection vulnerabilities are a result of passing untrusted input to an operating system shell, and may result in complete system compromise.

### Severity

This is a high severity finding. An attacker can exploit this vulnerability to take over your entire web server, stealing your database, and causing a major data breach incident. 

### How to verify this finding

The danger of command injection is that an attacker can send a malicious string which is passed to a call to `:os.cmd`. This function requires a charlist, for example:

```
iex(11)> :os.cmd('ls')
'CHANGELOG.md\nLICENSE\nREADME.md\nlib\nmix.exs\nmix.lock\ntest\n'
iex(12)> :os.cmd("ls")
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: not a list of characters

    (kernel 8.4.1) os.erl:434: :os.cmd("ls")
```

Follow this checklist to determine if user input can reach this function:

1. Start at the call to `:os.cmd` in your code base. Can you determine the source of this variable?

2. If it is hard-coded in the source code, user input does not change the variable, so the finding is a false-positive. 

3. If the variable comes from user input, for example a GET or POST request, the function is vulnerable. 

4. If the variable comes from a database, or other data store, you need to determine if it set by a user. 

If you are able to provide some input to your application, which changes the variable passed to `:os.cmd`, you have verified this finding as a true positive. 

### How to fix a true positive 

1. Consider removing the call to `:os.cmd`. Can you accomplish the same task without using this dangerous function? 

2.  If you must use `:os.cmd`, do not pass arbitrary user input to this function. Each input to this function should be pre-defined, not created dynamically with user input. 


## UID 2, CI.System: Command Injection in `System.cmd`

Command Injection vulnerabilities are a result of passing untrusted input to an operating system shell, and may result in complete system compromise.

### Severity

This is a high severity finding. An attacker can exploit this vulnerability to take over your entire web server, stealing your database, and causing a major data breach incident. 

### How to verify this finding

The danger of command injection is that an attacker can send a malicious string which is passed to a call to `System.cmd`. For example:

```
iex(16)> System.cmd("ls", [])
{"CHANGELOG.md\nLICENSE\nREADME.md\nlib\nmix.exs\nmix.lock\ntest\n", 0}
```

Follow this checklist to determine if user input can reach this function:

1. Start at the call to `System.cmd` in your code base. Can you determine the source of this variable?

2. If it is hard-coded in the source code, user input does not change the variable, so the finding is a false-positive. 

3. If the variable comes from user input, for example a GET or POST request, the function is vulnerable. 

4. If the variable comes from a database, or other data store, you need to determine if it set by a user. 

If you are able to provide some input to your application, which changes the variable passed to `System.cmd`, you have verified this finding as a true positive. 

### How to fix a true positive 

1. Consider removing the call to `System.cmd`. Can you accomplish the same task without using this dangerous function? 

2.  If you must use `System.cmd`, do not pass arbitrary user input to this function. Each input to this function should be pre-defined, not created dynamically with user input. 


## UID 3, Config.CSP: Missing Content-Security-Policy

Content-Security-Policy is an HTTP header that helps mitigate a number of attacks, including Cross-Site Scripting.

### Severity

This is a low severity finding. CSP is not a vulnerability, it is a layer of defense to stop XSS and data injection attacks. An attacker must exploit a XSS vulnerability that already exists for CSP to be relevant. 

### How to verify this finding

Check the HTTP response from your web server for the `content-security-policy` header. 

### How to fix a true positive 

Use `plug :put_secure_browser_headers` in your pipeline. Documentation on the `put_secure_browser_headers` plug functioncan be found here: https://hexdocs.pm/phoenix/Phoenix.Controller.html#put_secure_browser_headers/2

Note that adding a restrictive CSP header will improve security, but may break your application's front end JavaScript. Read https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP for more details. 


## UID 4, Config.CSRFRoute: CSRF via Action Reuse

In a Cross-Site Request Forgery (CSRF) attack, an untrusted application can cause a user's browser to submit requests or perform actions on the user's behalf.

### Severity

This is a medium severity finding. An attacker can create a malicious web page, and when a victim visits the web page, the attacker can force the victim's browser to perform an action in the web application. 

### How to verify this finding

In your Phoenix router, there should be two routes that use the same action, for example:

```
  get "/users/settings/edit_bio", UserSettingsController, :edit_bio
  post "/users/settings/edit_bio", UserSettingsController, :edit_bio
```

The POST request to `/users/settings/edit_bio` is not vulnerable to CSRF. Rather, it's the GET request to `/users/settings/edit_bio`, which contains the same parameters as the POST request in the URL, which is the source of this vulnerability. If you can issue a GET request that triggers the same functionality as the POST request, this finding is a true positive. 

For more detail see - https://paraxial.io/blog/action-reuse-csrf 

### How to fix a true positive 

1. Create different controller actions for each route. 

2. In the GET request route, do not allow state changing actions for authenticated user associated with a POST request. Examples of state changing actions are transferring money in a banking application, adding an admin user to a business management portal, or creating a new post on a social media website. 

## UID 5, Config.CSRF: Missing CSRF Protections

In a Cross-Site Request Forgery (CSRF) attack, an untrusted application can cause a user's browser to submit requests or perform actions on the user's behalf.

### Severity

This is a medium severity finding. An attacker can create a malicious web page, and when a victim visits the web page, the attacker can force the victim's browser to perform an action in the web application. 

### How to verify this finding

The root cause of this finding is a pipeline in your application's router file that fetches a session, but does not implement the `:protect_from_forgery` plug.

Locate an HTML form, which makes a POST request, matching this pipeline. For example:

```
<form action="/posts" method="post">

  <label for="post_title">Title</label>
  <input id="post_title" name="post[title]" type="text">

  <label for="post_body">Body</label>
  <textarea id="post_body" name="post[body]">
  </textarea>

  <div>
    <button type="submit">Save</button>
  </div>
</form>
```

This form is vulnerable to CSRF because there is no CSRF token. Note that even if there is a CSRF token in the form, such as:

```
<input name="_csrf_token" type="hidden" value="C3ceAlcYFxhHPC8WAnUfNCMsARUGJgZ5m9Rd5ZDG-HDVDDTMn_gHg_e8">
```

The form may still be vulnerable if the plug `:protect_from_forgery` is not present. 

To verify if the vulnerability is present, create a new file, `poc.html`, and enter the following: 

```
<form action="http://localhost:4000/posts" method="post" name="csrf_attack" style="">

  <input id="post_title" name="post[title]" value="Hacked">

  <input id="post_body" name="post[body]" value="Hacked by Dogs">

  <div>
    <button type="submit">Save</button>
  </div>
</form>
```

Ensure you are logged into the vulnerable application with a valid session, then open `poc.html` in the same web browser. If submitting this form performs the action in your account, in this case creating a post, the vulnerability exists. 


### How to fix a true positive 

1. Ensure you are using the `:protect_from_forgery` plug in pipelines that fetch a session. 

2. The HTML form should be created with a Phoenix helper, such as `form_for`, because it automatically includes the CSRF token - https://hexdocs.pm/phoenix_html/Phoenix.HTML.Form.html#form_for/4 If the matching form does not have a CSRF token, the vulnerability is not fixed. 


## UID 6, Config.CSWH: Cross-Site Websocket Hijacking

Websocket connections are not bound by the same-origin policy. Connections that do not validate the origin may leak information to an attacker.

### Severity

### How to verify this finding

### How to fix a true positive 


## UID 7, Config.Headers: Missing Secure Browser Headers

By default, Phoenix HTTP responses contain a number of secure HTTP headers that attempt to mitigate XSS, click-jacking, and content-sniffing attacks.

Missing Secure HTTP Headers is flagged by `sobelow` when a pipeline accepts "html" requests, but does not implement the `:put_secure_browser_headers` plug.

### Severity

This is a low severity finding. Missing secure browser headers is not a vulnerability. Having these headers is considered a best practice. 

### How to verify this finding

Most Phoenix applications set these headers by default. This finding is triggered when a router pipeline accepts `html` requests, but does not implement the `:put_secure_browser_headers` plug.

Check the response of a request in this pipeline for the headers:

```
referrer-policy
x-frame-options
x-content-type-options
x-download-options 
x-permitted-cross-domain-policies 
```

https://hexdocs.pm/phoenix/Phoenix.Controller.html#put_secure_browser_headers/2

### How to fix a true positive 

Add the plug `:put_secure_browser_headers` to the pipeline. 


## UID 8, Config.HSTS: HSTS Not Enabled

The HTTP Strict Transport Security (HSTS) header helps defend against man-in-the-middle attacks by preventing unencrypted connections.

### Severity

This is a medium severity finding. The HSTS header is used to defend against man-in-the-middle attacks by preventing unencrypted connections.

### How to verify this finding

Check your config file for:

```elixir
config :havana, HavanaWeb.Endpoint,
  force_ssl: [hsts: true]
```

Remember that Sobelow is limited to your Phoenix application code. Your deployed application may be using HSTS correctly, due to a server level configuration. Use https://www.ssllabs.com/ssltest/ to verify your deployed settings. 

https://hexdocs.pm/phoenix/using_ssl.html#hsts

https://hexdocs.pm/plug/Plug.SSL.html

### How to fix a true positive 

Set the following config:

```
config :havana, HavanaWeb.Endpoint,
  force_ssl: [hsts: true]
```

Replace "Havana" with your application name. Use https://www.ssllabs.com/ssltest/ to verify your deployed settings. 


## UID 9, Config.HTTPS: HTTPS Not Enabled

Without HTTPS, attackers in a privileged network position can intercept and modify traffic. Sobelow detects missing HTTPS by checking the prod configuration.

### Severity

This is a high severity finding. Using HTTPS is a requirement if your application handles user data. 

### How to verify this finding

This finding is often a false positive, because HTTPS configuration may be set at a different layer in the application stack. For example, your web server may be configured to force HTTPS. 

Use https://www.ssllabs.com/ssltest/ on the deployed server to test the HTTPS configuration. 

### How to fix a true positive 

Configure your Phoenix application to use HTTPS - https://hexdocs.pm/phoenix/using_ssl.html#content


## UID 10, Config.Secrets: Hardcoded Secret

### Severity

This is a medium severity finding. Hard coding secrets in source code is not recommended.

### How to verify this finding

Sobelow checks for configuration variables such as `secret_key_base`, `password`, and `secret` with a matching string. Read the finding, and determine if the value stored in source code is a true secret. 

### How to fix a true positive 

The best practice for secrets is to store them as environment variables. 



## UID 11, DOS.BinToAtom: Unsafe atom interpolation

In Elixir, atoms are not garbage collected. As such, if user input is used to create atoms (as in `:"foo\#{bar}"`, or in `:erlang.binary_to_atom`), it may result in memory exhaustion. Prefer the `String.to_existing_atom` function for untrusted user input.

### Severity

This is a medium severity finding. It does not allow the attacker to access private data, or performed unauthorized actions. Atom DoS allows an attacker to trigger a crash of the Erlang virtual machine. There are two possible outcomes:

1. The application crashes and restarts. There will be some downtime during the restart, but overall the impact will be low.

2. The application crashes and remains down. This is a higher severity incident.

The behavior of your application depends on the deployment environment. Instructions for testing your environment - https://paraxial.io/blog/atom-dos-impact 

### How to verify this finding

Find the line of code where the atom is being created. Is the atom created from user input? For example:

`:new_atom_#{a}`

Can the variable `a` be set through user input? If it can be, this is a true positive. 

### How to fix a true positive 

Do not create new atoms at runtime. Restructure your code so that atoms do not need to be created from user input. 

https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/atom_exhaustion


## UID 12, DOS.ListToAtom: Unsafe `List.to_atom`

In Elixir, atoms are not garbage collected. As such, if user input is passed to the `List.to_atom` function, it may result in memory exhaustion. Prefer the `List.to_existing_atom` function for untrusted user input.

### Severity

This is a medium severity finding. It does not allow the attacker to access private data, or performed unauthorized actions. Atom DoS allows an attacker to trigger a crash of the Erlang virtual machine. There are two possible outcomes:

1. The application crashes and restarts. There will be some downtime during the restart, but overall the impact will be low.

2. The application crashes and remains down. This is a higher severity incident.

The behavior of your application depends on the deployment environment. Instructions for testing your environment - https://paraxial.io/blog/atom-dos-impact 

### How to verify this finding

Find the line of code where the atom is being created. Is the atom created from user input? For example:

`List.to_atom(a)`

Can the variable `a` be set through user input? If it can be, this is a true positive. 

### How to fix a true positive 

Do not create new atoms at runtime. Restructure your code so that atoms do not need to be created from user input. 

https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/atom_exhaustion


## UID 13, DOS.StringToAtom: Unsafe `String.to_atom`

In Elixir, atoms are not garbage collected. As such, if user input is passed to the `String.to_atom` function, it may result in memory exhaustion. Prefer the `String.to_existing_atom` function for untrusted user input.

### Severity

This is a medium severity finding. It does not allow the attacker to access private data, or performed unauthorized actions. Atom DoS allows an attacker to trigger a crash of the Erlang virtual machine. There are two possible outcomes:

1. The application crashes and restarts. There will be some downtime during the restart, but overall the impact will be low.

2. The application crashes and remains down. This is a higher severity incident.

The behavior of your application depends on the deployment environment. Instructions for testing your environment - https://paraxial.io/blog/atom-dos-impact 

### How to verify this finding

Find the line of code where the atom is being created. Is the atom created from user input? For example:

`String.to_atom(a)`

Can the variable `a` be set through user input? If it can be, this is a true positive. 

### How to fix a true positive 

Do not create new atoms at runtime. Restructure your code so that atoms do not need to be created from user input. 

https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/atom_exhaustion


## UID 14, Misc.BinToTerm: Unsafe `binary_to_term`

If user input is passed to Erlang's `binary_to_term` function it may result in memory exhaustion or code execution. Even with the `:safe` option, `binary_to_term` will deserialize functions, and shouldn't be considered safe to use with untrusted input.

### Severity

This is a high severity finding. Unsafe usage of `binary_to_term` can lead to a remote code execution vulnerability, which allows an attacker to take over your web server. 

### How to verify this finding

Is user input being passed to `binary_to_term`? For example:

`:erlang.binary_to_term(user_input, [:safe])`

The [:safe] option is misleading, this function is vulnerable. If user input is being passed to `binary_to_term`, this is a true positive. 

https://paraxial.io/blog/elixir-rce


### How to fix a true positive 

Use `Plug.Crypto.non_executable_binary_to_term` instead. 

https://hexdocs.pm/plug_crypto/Plug.Crypto.html#non_executable_binary_to_term/2


## UID 15, RCE.CodeModule: Code execution in eval function

### Severity

This is a high severity finding. Calling the `Code` functions `eval_string`, `eval_file`, or `eval_quoted` on external user input may allow an attacker to take over your web server. 

### How to verify this finding

Is user input being passed to the function that Sobelow flagged? For example:

`Code.eval_string(user_input)`

If the function is receiving user input, this is a true positive. 

### How to fix a true positive 

Do not allow user input to reach the `Code` functions `eval_string`, `eval_file`, or `eval_quoted`. Input to these functions should never come from the network. 

https://hexdocs.pm/elixir/Code.html

## UID 16, RCE.EEx: Code Execution in EEx template eval

If user input is passed to EEx eval functions, it may result in arbitrary code execution. The root cause of these issues is often directory traversal.

### Severity

This is a high severity finding. Calling the EEx functions `eval_string` and `eval_file` on external user input may allow an attacker to take over your web server. 

### How to verify this finding

Is user input being passed to the function that Sobelow flagged? For example:

```
> user_input = "<%= 2 + 3 %>"
"<%= 2 + 3 %>"
> EEx.eval_string(user_input)      
"5"
```

If the function is receiving user input, this is a true positive. 

### How to fix a true positive 

Do not allow user input to reach the `EEx` functions `eval_string` and `eval_file`. Input to these functions should never come from the network. 

https://hexdocs.pm/eex/1.14/EEx.html

## UID 17, SQL.Query: SQL injection

### Severity

This is a high severity finding. SQL injection can be used by an attacker to run authorized database commands, leading to data being stolen, modified, or deleted. 

### How to verify this finding

Below is an example of code that is vulnerable to SQL injection:

```
  def e_get_fruit(min_q) do
    q = """
    SELECT f.id, f.name, f.quantity, f.secret
    FROM fruits AS f
    WHERE f.quantity > #{min_q} AND f.secret = FALSE
    """
    {:ok, %{rows: rows}} =
      Ecto.Adapters.SQL.query(Repo, q)
  end
```

The key line is `WHERE f.quantity > #{min_q} AND f.secret = FALSE`, where `min_q` is user input. You should never construct an SQL query from user input. Rather, external input should be passed as a parameter to the query. For example:

`Ecto.Adapters.SQL.query(MyRepo, "SELECT $1::integer + $2", [user_in_a, user_in_b])`

is not vulnerable, because the user input `(user_in_a, user_in_b)` is being passed as parameters to the SQL query. 

https://paraxial.io/blog/sql-injection

### How to fix a true positive 

Ensure that all user input is passed as a parameter to the `query` function. 

Not safe:

`Ecto.Adapters.SQL.query(Repo, "SELECT * FROM potions WHERE name = #{user_input}")`

Not safe:

`Ecto.Adapters.SQL.query(Repo, "SELECT * FROM potions WHERE name = " <> user_input)`

Safe:

`Ecto.Adapters.SQL.query(Repo, "SELECT * FROM potions WHERE name = $1", [user_input])`


## UID 18, SQL.Stream: SQL injection

### Severity

This is a high severity finding. SQL injection can be used by an attacker to run authorized database commands, leading to data being stolen, modified, or deleted. 

### How to verify this finding

Below is an example of code that is vulnerable to SQL injection:

```
  def e_get_fruit(min_q) do
    q = """
    SELECT f.id, f.name, f.quantity, f.secret
    FROM fruits AS f
    WHERE f.quantity > #{min_q} AND f.secret = FALSE
    """
    Ecto.Adapters.SQL.stream(Repo, q)
  end
```

The key line is `WHERE f.quantity > #{min_q} AND f.secret = FALSE`, where `min_q` is user input. You should never construct an SQL query from user input. Rather, external input should be passed as a parameter to the query. For example:

`Ecto.Adapters.SQL.stream(MyRepo, "SELECT $1::integer + $2", [user_in_a, user_in_b])`

is not vulnerable, because the user input `(user_in_a, user_in_b)` is being passed as parameters to the SQL query. 

https://paraxial.io/blog/sql-injection

### How to fix a true positive 

Ensure that all user input is passed as a parameter to the `query` function. 

Not safe:

`Ecto.Adapters.SQL.stream(Repo, "SELECT * FROM potions WHERE name = #{user_input}")`

Not safe:

`Ecto.Adapters.SQL.stream(Repo, "SELECT * FROM potions WHERE name = " <> user_input)`

Safe:

`Ecto.Adapters.SQL.stream(Repo, "SELECT * FROM potions WHERE name = $1", [user_input])`


## UID 19, Traversal.FileModule: Directory Traversal in `File` function

### Severity

This is a high severity finding. If user input is passed to a `File` function, an attacker may be able to read unauthorized files, such as `../config/prod.secrets.exs`, and make unauthorized changes to the filesystem. 

### How to verify this finding

1. Start at the call to the `File` function in your code base. Can you determine the source of this variable?

2. If it is hard-coded in the source code, user input does not change the variable, so the finding is a false-positive. 

3. If the variable comes from user input, for example a GET or POST request, the function is vulnerable. 

4. If the variable comes from a database, or other data store, you need to determine if it set by a user. 

If you are able to provide some input to your application, which changes the variable passed to the `File` function, you have verified this finding as a true positive. 

### How to fix a true positive 

Do not pass user input to `File` functions. The input should be system generated, for example: 

`%Plug.Upload{filename: filename, path: path} = upload`

When `upload` is set by the user, it is not safe to pass the `filename` variable. The `path` variable is generated by plug, for example:

`/var/folders/0m/d5lzvxvs181cl_f5m1x3wrx40000gn/T/plug-1681/multipart-1681411044-723629749623759-3`

and is safe to pass as a variable. 


## UID 20, Traversal.SendDownload: Directory Traversal in `send_download`

### Severity

This is a high severity finding. If user input is passed to `send_download`, an attacker may be able to read unauthorized files, such as `../config/prod.secrets.exs`, and make unauthorized changes to the filesystem. 

### How to verify this finding

Consider the example function in a Phoenix controlelr:

```elixir
def user_pfp(conn, %{"file_name" => file_name}) do
  send_download(conn, {:file, file_name})
end
```

When `file_name` is controlled by the user, this is a true positive. 

1. Start at the call to the `send_download` function in your code base. Can you determine the source of the function input? 

2. If the function input is hard-coded in source, it is a false-positive. 

3. If the variable comes from user input, for example a GET or POST request, the function is vulnerable. 

4. If the variable comes from a database, or other data store, you need to determine if it set by a user. 

If you are able to provide some input to your application, which changes the variable passed to the `send_download` function, you have verified this finding as a true positive. 

### How to fix a true positive 

Do not pass user input to `send_download`. Inputs to `send_download` should be pre-defined in the source code, not created dynamically by user input. 


## UID 21, Traversal.SendFile: Directory Traversal in `send_file`

### Severity

This is a high severity finding. If user input is passed to `send_file`, an attacker may be able to read unauthorized files, such as `../config/prod.secrets.exs`, and make unauthorized changes to the filesystem. 

### How to verify this finding

Consider the example function in a Phoenix controlelr:

```elixir
def user_pfp(conn, %{"file_name" => file_name}) do
  send_file(conn, 200, file_name)
end
```

When `file_name` is controlled by the user, this is a true positive. 

1. Start at the call to the `send_file` function in your code base. Can you determine the source of the function input? 

2. If the function input is hard-coded in source, it is a false-positive. 

3. If the variable comes from user input, for example a GET or POST request, the function is vulnerable. 

4. If the variable comes from a database, or other data store, you need to determine if it set by a user. 

If you are able to provide some input to your application, which changes the variable passed to the `send_file` function, you have verified this finding as a true positive. 

### How to fix a true positive 

Do not pass user input to `send_file`. Inputs to `send_file` should be pre-defined in the source code, not created dynamically by user input. 


## UID 22, Vuln.Coherence: Known Vulnerable Dependency - Update Coherence

### Severity

This is a high severity vulnerability. An attacker can add themselves as an admin user, see the Github issue for more details -  https://github.com/smpallen99/coherence/issues/270

https://github.com/advisories/GHSA-mrq8-53r4-3j5m


### How to verify this finding

Check if you are using `coherence` version `<= 0.5.1`. If you are, this is a true positive. 

### How to fix a true positive 

Upgrade to `0.5.2` or later. 


## UID 23, Vuln.Plug: Known Vulnerable Dependency - Update Plug

### Severity

This is a high severity vulnerability. See this post from Jose Valim for more details - https://elixirforum.com/t/static-and-session-security-fixes-for-plug

https://github.com/advisories/GHSA-5v4m-c73v-c7gq

### How to verify this finding

Check if the version of Plug you are using matches: `Plug v1.3.1, v1.3.0, v1.2.2, v1.2.1, v1.2.0, v1.1.6, v1.1.5, v1.1.4, v1.1.3, v1.1.2, v1.1.1, v1.1.0, v1.0.3, v1.0.2, v1.0.1, v1.0.0`

### How to fix a true positive 

Upgrade to `Plug v1.3.2+, v1.2.3+, v1.1.7+, v1.0.4+`

https://hex.pm/packages/plug

## UID 24, Vuln.Ecto: Known Vulnerable Dependency - Update Ecto

### Severity

This is a high severity finding. Ecto `2.2.0` does not enforce the `is_nil` requirement. For an example of why this is dangerous, see this example from Jose Valim:

Imagine you write this query:

`from User, where: [api_token: ^params["token"]], limit: 1`

Now if someone passes no token, you will accidentally login as any of the users without a token.


https://elixirforum.com/t/why-does-ecto-require-the-use-of-is-nil-1/49241

https://groups.google.com/g/elixir-ecto/c/0m4NPfg_MMU

https://github.com/advisories/GHSA-4r2f-6fm9-2qgh

### How to verify this finding

If you are using Ecto version `2.2.0`, it is a true positive.

### How to fix a true positive 

Upgrade to a version of Ecto after `2.2.0`.


## UID 25, Vuln.HeaderInject: Known Vulnerable Dependency - Update Plug

### Severity

This is a high severity vulnerability. See this post from Jose Valim for more details - https://elixirforum.com/t/static-and-session-security-fixes-for-plug

https://github.com/advisories/GHSA-2q6v-32mr-8p8x

### How to verify this finding

If you are using plug version:

`"<=1.3.4 and >=1.3.0", "<=1.2.4 and >=1.2.0", "<=1.1.8 and >=1.1.0", "<=1.0.5"`

This is a true positive. 

### How to fix a true positive 

Upgrade to a secure version of Plug. 

https://hex.pm/packages/plug

## FindingHere

### Severity

### How to verify this finding

### How to fix a true positive 


## FindingHere

### Severity

### How to verify this finding

### How to fix a true positive 


## FindingHere

### Severity

### How to verify this finding

### How to fix a true positive 


## FindingHere

### Severity

### How to verify this finding

### How to fix a true positive 


## FindingHere

### Severity

### How to verify this finding

### How to fix a true positive 

