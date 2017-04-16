defmodule Sobelow.XSS do
  alias Sobelow.Utils

  def get_vulns(fun, filename, web_root) do
    render_funs = Utils.parse_render_def(fun)
    {ref_vars, is_html, params, {fun_name, [{_, line_no}]}} = Utils.parse_send_resp_def(fun)

    controller = String.replace_suffix(filename, "_controller.ex", "")
    controller = String.replace_prefix(controller, "/controllers/", "")
    controller = String.replace_prefix(controller, "/web/controllers/", "")
    con = String.replace_prefix(filename, "/", "")

    Enum.each render_funs, fn {template_name, ref_vars, vars, params, {fun_name, [{_, line_no}]}} ->
      if is_atom(template_name) do
        template_name = Atom.to_string(template_name) <> ".html"
      end

      if is_list(template_name) do
        template_name = ".html"
      end

      p = web_root <> "templates/" <> controller <> "/" <> template_name <> ".eex"
      if File.exists?(p) do
        raw_vals = Utils.get_template_raw_vars(p)
        Enum.each(ref_vars, fn var ->
          if Enum.member?(raw_vals, var) do
            t_name = String.replace_prefix(Path.expand(p, ""), "/", "")
            print_finding(t_name, line_no, con, fun_name, var, :high)
          end
        end)

        Enum.each(vars, fn var ->
          if Enum.member?(raw_vals, var) do
            t_name = String.replace_prefix(Path.expand(p, ""), "/", "")
            print_finding(t_name, line_no, con, fun_name, var, :medium)
          end
        end)
      end
    end

    Enum.each ref_vars, fn var ->
      if is_list(var) do
        Enum.each var, fn v ->
          if (Enum.member?(params, v) || v === "conn.params") && is_html do
            print_resp_finding(line_no, con, fun_name, fun, v, :high)
          end

          if is_html && !Enum.member?(params, v) do
            print_resp_finding(line_no, con, fun_name, fun, v, :medium)
          end
        end
      else
        if (Enum.member?(params, var) || var === "conn.params") && is_html do
          print_resp_finding(line_no, con, fun_name, fun, var, :high)
        end

        if is_html && !Enum.member?(params, var) && var != "conn.params" do
          print_resp_finding(line_no, con, fun_name, fun, var, :medium)
        end
      end
    end

  end

  defp print_resp_finding(line_no, con, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "XSS in `send_resp` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :send_resp)
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(t_name, line_no, con, fun_name, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "XSS - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{var}"
    IO.puts "\n-----------------------------------------------\n"
  end
end