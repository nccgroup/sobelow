defmodule Sobelow.XSS do
  alias Sobelow.Utils
  alias Sobelow.XSS.{SendResp, Raw}
  @submodules [Sobelow.XSS.SendResp,
               Sobelow.XSS.Raw]

  def get_vulns(fun, filename, web_root) do
    controller = String.replace_suffix(filename, "_controller.ex", "")
    controller = String.replace_prefix(controller, "/controllers/", "")
    controller = String.replace_prefix(controller, "/web/controllers/", "")
    con = String.replace_prefix(filename, "/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      if mod === Raw do
        apply(mod, :run, [fun, filename, web_root, con, controller])
      else
        apply(mod, :run, [fun, filename, con])
      end
    end
  end
end