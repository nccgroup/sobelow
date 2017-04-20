defmodule Sobelow.XSS do
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