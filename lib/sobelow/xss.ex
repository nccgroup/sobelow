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
  @submodules [Sobelow.XSS.SendResp, Sobelow.XSS.ContentType, Sobelow.XSS.Raw, Sobelow.XSS.HTML]

  use Sobelow.FindingType

  def get_vulns(fun, meta_file, web_root, skip_mods \\ []) do
    controller =
      if meta_file.is_controller? do
        String.replace_suffix(meta_file.filename, "_controller.ex", "")
        |> Path.basename()
      end

    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each(allowed, fn mod ->
      if mod === Raw do
        apply(mod, :run, [fun, meta_file, web_root, controller])
      else
        apply(mod, :run, [fun, meta_file])
      end
    end)
  end

  def get_template_vulns(meta_file) do
    allowed = @submodules -- Sobelow.get_ignored()
    funs = meta_file.raw

    if Enum.member?(allowed, Raw) do
      Enum.each(funs, fn fun ->
        apply(Raw, :run, [[fun], meta_file, nil, nil])
      end)
    end
  end

  def details() do
    @moduledoc
  end
end
