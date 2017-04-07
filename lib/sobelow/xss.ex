defmodule Sobelow.XSS do
  alias Sobelow.Utils

  def reflected_xss(web_root) do
#    web_root = "../hexpm/lib/hexpm/web/"

    all_controllers(web_root <> "controllers/")
    |> Enum.each(fn cont -> find_vulnerable_ref(cont, web_root <> "controllers/") end)
  end

  defp find_vulnerable_ref(controller_path, controller_root) do
    def_funs = Utils.get_def_funs(controller_root <> controller_path)
    |> Enum.map(&Utils.parse_fun_def(&1))
    |> Enum.reject(fn fun -> Enum.empty?(fun) end)

    controller = String.replace_suffix(controller_path, "_controller.ex", "")

    Enum.each def_funs, fn funs ->
      Enum.each(funs, fn {template_name, vars} ->
        [{temp, _}|_] = funs

        if is_atom(temp) do
          temp = Atom.to_string(temp) <> ".html"
        end

        p = controller_root <> "../templates/" <> controller <> "/" <> temp <> ".eex"

        if File.exists?(p) do
          raw_vals = Utils.get_template_raw_vars(p)
          IO.inspect {Enum.any?(vars, fn var -> Enum.member?(raw_vals, var) end), template_name}
        end
      end)
    end

  end

  defp all_controllers(root_path) do
    Utils.all_files(root_path)
  end
end