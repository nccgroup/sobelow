defmodule Sobelow.XSS do
  @moduledoc """
  # Cross-Site Scripting

  Cross-Site Scripting (XSS) vulnerabilities are a result
  of rendering untrusted input on a page without proper encoding.
  XSS may allow an attacker to perform actions on behalf of
  other users, steal session tokens, or access private data.

  Read more about XSS here:
  https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)

  XSS checks can be ignored with the following command:

      $ mix sobelow -i XSS
  """
  alias Sobelow.XSS.Raw
  @submodules [Sobelow.XSS.SendResp,
               Sobelow.XSS.ContentType,
               Sobelow.XSS.Raw]

  use Sobelow.Finding

  def get_vulns(fun, filename, web_root, skip_mods \\ []) do
    controller = if String.contains?(filename, "_controller.ex") do
      String.replace_suffix(filename, "_controller.ex", "")
      |> Path.basename()
    end

    path = Path.expand(filename, "")
    |> String.replace_prefix("/", "")

    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each allowed, fn mod ->
      if mod === Raw do
        apply(mod, :run, [fun, path, web_root, controller])
      else
        apply(mod, :run, [fun, path])
      end
    end
  end
end