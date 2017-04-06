defmodule Sobelow.XSS do
  alias Sobelow.Utils

  def reflected_xss(web_root) do
    path = "../hex/hexpm/lib/hexpm/web/controllers/login_controller.ex"

    all_controllers(web_root <> "controllers")
    |> Enum.each(fn cont -> find_vulnerable_ref(cont, web_root) end)




#    def_funs = Utils.get_def_funs(path)
#    |> Enum.map(&Utils.parse_fun_def(&1))
#    |> Enum.reject(fn fun -> Enum.empty?(fun) end)
#
#    template_path = "../hex/hexpm/lib/hexpm/web/templates/login/show.html.eex"
#    raw_vals = Utils.get_template_raw_vars(template_path)
#
#    Enum.each def_funs, fn funs ->
#      Enum.each(funs, fn {template_name, vars} ->
#        Enum.any?(vars, fn var -> Enum.member?(raw_vals, var) end)
#      end)
#    end
  end

  defp find_vulnerable_ref(path, controller_root) do
    def_funs = Utils.get_def_funs("../hex/hexpm/lib/hexpm/web/controllers/" <> path)
    |> Enum.map(&Utils.parse_fun_def(&1))
    |> Enum.reject(fn fun -> Enum.empty?(fun) end)

    controller = String.replace_suffix(path, "_controller.ex", "")

    Enum.each def_funs, fn funs ->
      Enum.each(funs, fn {template_name, vars} ->
        [{temp, _}|_] = funs
        p = "../hex/hexpm/lib/hexpm/web/templates/" <> controller <> "/" <> temp <> ".eex"

        if File.exists?(p) do
          raw_vals = Utils.get_template_raw_vars(p)
          IO.inspect {Enum.any?(vars, fn var -> Enum.member?(raw_vals, var) end), template_name}
        end
      end)
    end

  end

  defp all_controllers(root_path) do
    Utils.all_files("../hex/hexpm/lib/hexpm/web/controllers/")
  end
end