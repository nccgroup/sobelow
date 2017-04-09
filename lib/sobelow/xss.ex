defmodule Sobelow.XSS do
  alias Sobelow.Utils

  def reflected_xss(web_root) do
    # Used for testing until I create a real broken demo app.
    # web_root = "../hexpm/lib/hexpm/web/"

    IO.puts IO.ANSI.cyan_background() <>
      IO.ANSI.black() <>
      "Searching for Cross-Site Scripting (XSS) Vulnerabilities" <>
      IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"

    all_controllers(web_root <> "controllers/")
    |> Enum.each(fn cont -> find_vulnerable_ref(cont, web_root <> "controllers/") end)
  end

  defp find_vulnerable_ref(controller_path, controller_root) do
    def_funs = Utils.get_def_funs(controller_root <> controller_path)
    |> Enum.map(&Utils.parse_fun_def(&1))
    |> Enum.reject(fn fun -> Enum.empty?(fun) end)

    controller = String.replace_suffix(controller_path, "_controller.ex", "")

    Enum.each def_funs, fn funs ->
      Enum.each(funs, fn {template_name, ref_vars, vars, params, {fun_name, [{_, line_no}]}} ->
        if is_atom(template_name) do
          template_name = Atom.to_string(template_name) <> ".html"
        end

        # Found test case where user was choosing template via function call. :(
        # Ultimately, should render without this.
        if is_list(template_name) do
          template_name = ".html"
        end

        p = controller_root <> "../templates/" <> controller <> "/" <> template_name <> ".eex"

        if File.exists?(p) do
          raw_vals = Utils.get_template_raw_vars(p)
          Enum.each(ref_vars, fn var ->
            if Enum.member?(raw_vals, var) do
              t_name = String.replace_prefix(Path.expand(p, ""), "/", "")
              con = String.replace_prefix(controller, "/", "")
              print_finding(t_name, line_no, con, fun_name, var, :high)
            end
          end)

          Enum.each(vars, fn var ->
            if Enum.member?(raw_vals, var) do
              t_name = String.replace_prefix(Path.expand(p, ""), "/", "")
              con = String.replace_prefix(controller, "/", "")
              print_finding(t_name, line_no, con, fun_name, var, :medium)
            end
          end)
        end
      end)
    end

  end

  defp all_controllers(root_path) do
    Utils.all_files(root_path)
  end

  defp print_finding(t_name, line_no, con, fun_name, variable, :high) do
    IO.puts IO.ANSI.red() <> "XSS discovered - Highly Likely" <> IO.ANSI.reset()
    IO.puts "Controller: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{variable}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(t_name, line_no, con, fun_name, variable, :medium) do
    IO.puts IO.ANSI.yellow() <> "XSS discovered - Possible" <> IO.ANSI.reset()
    IO.puts "Controller: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{variable}"
    IO.puts "\n-----------------------------------------------\n"
  end
end