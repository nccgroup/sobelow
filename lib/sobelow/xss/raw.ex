defmodule Sobelow.XSS.Raw do
  alias Sobelow.Utils

  def run(fun, filename, web_root, controller) do
    render_funs = parse_render_def(fun)

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
            print_finding(t_name, line_no, filename, fun_name, fun, var, :high)
          end
        end)

        Enum.each(vars, fn var ->
          if Enum.member?(raw_vals, var) do
            t_name = String.replace_prefix(Path.expand(p, ""), "/", "")
            print_finding(t_name, line_no, filename, fun_name, fun, var, :medium)
          end
        end)
      end
    end
  end

  def parse_render_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    Utils.get_funs_of_type(fun, :render)
    |> Enum.map(&Utils.parse_render_opts(&1, params, {fun_name, line_no}))
  end

  defp print_finding(t_name, line_no, con, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "XSS - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Template: #{t_name} - @#{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :render)
    IO.puts "\n-----------------------------------------------\n"
  end
end