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

    render_funs = Enum.map(def_funs, &Utils.parse_fun_def(&1))
    |> Enum.reject(fn fun -> Enum.empty?(fun) end)

    resp_funs = Enum.map(def_funs, &Utils.parse_send_resp_def(&1))
    |> Enum.reject(fn {vars, _, _, _} -> Enum.empty?(vars) end)

    controller = String.replace_suffix(controller_path, "_controller.ex", "")
    con = String.replace_prefix(controller, "/", "")

    Enum.each render_funs, fn funs ->
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

    Enum.each resp_funs, fn {ref_vars, is_html, params, {fun_name, [{_, line_no}]}} ->
      Enum.each ref_vars, fn var ->
        if Enum.member?(params, var) && is_html || is_html do
          print_finding(line_no, con, fun_name, var, :high)
        else
          print_finding(line_no, con, fun_name, var, :low)
        end
      end
    end

  end

  defp all_controllers(root_path) do
    Utils.all_files(root_path)
  end

  defp print_finding(line_no, con, fun_name, var, :high) do
    IO.puts IO.ANSI.red() <> "XSS in `send_resp` - High Confidence" <> IO.ANSI.reset()
    IO.puts "Controller: #{con}_controller - #{fun_name}:#{line_no}"
    IO.puts "send_resp var: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, :low) do
    IO.puts IO.ANSI.green() <> "XSS in `send_resp` - Low Confidence" <> IO.ANSI.reset()
    IO.puts "Controller: #{con}_controller - #{fun_name}:#{line_no}"
    IO.puts "send_resp var: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(t_name, line_no, con, fun_name, variable, :high) do
    IO.puts IO.ANSI.red() <> "XSS - High Confidence" <> IO.ANSI.reset()
    IO.puts "Controller: #{con}_controller - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{variable}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(t_name, line_no, con, fun_name, variable, :medium) do
    IO.puts IO.ANSI.yellow() <> "XSS - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "Controller: #{con}_controller - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{variable}"
    IO.puts "\n-----------------------------------------------\n"
  end
end