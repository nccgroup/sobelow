defmodule Sobelow.XSS do
  @moduledoc """
  Cross-Site Scripting (XSS) vulnerabilities are a result
  of rendering untrusted input on a page without proper encoding.
  XSS may allow an attacker to perform actions on behalf of
  other users, steal session tokens, or access private data.

  Read more about XSS here:
  https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)

  XSS checks can be ignored with the following command:

      $ mix sobelow -i XSS
  """
  alias Sobelow.Utils
  alias Sobelow.XSS.{SendResp, Raw}
  @submodules [Sobelow.XSS.SendResp,
               Sobelow.XSS.Raw]

  def get_vulns(fun, filename, web_root) do
    controller = String.replace_suffix(filename, "_controller.ex", "")
    controller = String.replace_prefix(controller, "/controllers/", "")
    controller = String.replace_prefix(controller, "/web/controllers/", "")
    path = web_root <> String.replace_prefix(filename, "/web/", "")
    |> Path.expand("")
    |> String.replace_prefix("/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      if mod === Raw do
        apply(mod, :run, [fun, path, web_root, controller])
      else
        apply(mod, :run, [fun, path])
      end
    end
  end
end