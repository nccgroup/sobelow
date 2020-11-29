defmodule Sobelow.Traversal do
  @moduledoc """
  # Path Traversal

  Path traversal vulnerabilities are a result of
  interacting with the filesystem using untrusted input.
  This class of vulnerability may result in file disclosure,
  code execution, denial of service, and other issues.

  Read more about Path Traversal here:
  https://www.owasp.org/index.php/Path_Traversal

  Path Traversal checks can be ignored with the following command:

      $ mix sobelow -i Traversal
  """
  @submodules [
    Sobelow.Traversal.SendFile,
    Sobelow.Traversal.FileModule,
    Sobelow.Traversal.SendDownload
  ]

  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [fun, meta_file])
    end)
  end

  def details() do
    @moduledoc
  end
end
