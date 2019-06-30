defmodule Sobelow.Misc.FilePath do
  @moduledoc ~S"""
  # Insecure use of `File` and `Path`

  Note: This check has been deprecated. File/Path issues were
  addressed with the release of OTP 21.

  In Elixir, `File` methods are null-terminated, while `Path`
  functions are not. This may cause security issues in certain
  situations. For example:

  ```
  user_input = "/var/www/secret.txt\0/name"

  path = Path.dirname(user_input)
  public_file = path <> "/public.txt"

  File.read(public_file)
  ```

  Because `Path` functions are not null-terminated, this
  will attempt to read the file, "/var/www/secret.txt\\0/public.txt".
  However, due to the null-byte termination of `File` functions
  "secret.txt" will ultimately be read.

  `File/Path` checks can be ignored with the following command:

      $ mix sobelow -i Misc.FilePath
  """
end
