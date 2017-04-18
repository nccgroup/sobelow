defmodule Sobelow.XSS do
  alias Sobelow.Utils
  alias Sobelow.XSS.{SendResp, Raw}

  def get_vulns(fun, filename, web_root) do
    controller = String.replace_suffix(filename, "_controller.ex", "")
    controller = String.replace_prefix(controller, "/controllers/", "")
    controller = String.replace_prefix(controller, "/web/controllers/", "")
    con = String.replace_prefix(filename, "/", "")

    Raw.run(fun, filename, web_root, con, controller)
    SendResp.run(fun, filename, con)
  end
end