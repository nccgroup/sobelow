defmodule Sobelow.XSS.Raw do
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "XSS"

  def run(fun, meta_file, _, nil) do
    severity = if meta_file.is_controller?, do: false, else: :low

    {vars, params, {fun_name, [{_, line_no}]}} = parse_raw_def(fun)

    Enum.each(vars, fn {finding, var} ->
      Utils.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Utils.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  def run(fun, meta_file, web_root, controller) do
    {vars, _, {fun_name, [{_, line_no}]}} = parse_render_def(fun)
    filename = meta_file.filename
    templates = Sobelow.MetaLog.get_templates()

    root =
      if String.ends_with?(web_root, "/lib/") do
        app_name = Sobelow.get_env(:app_name)
        prc = web_root <> app_name <> "_web/"
        rc = web_root <> app_name <> "/web/"
        Enum.find([rc, prc], "", &File.exists?/1)
      else
        web_root
      end

    Enum.each(vars, fn {finding, {template, ref_vars, vars}} ->
      template =
        cond do
          is_atom(template) -> Atom.to_string(template) <> ".html"
          is_binary(template) -> template
          true -> ""
        end

      template_path =
        (root <> "templates/" <> controller <> "/" <> template <> ".eex")
        |> Utils.normalize_path()

      raw_funs = templates[template_path]

      if raw_funs do
        raw_vals = Utils.get_template_vars(raw_funs.raw)

        Enum.each(ref_vars, fn var ->
          var = "@#{var}"
          if Enum.member?(raw_vals, var) do
            Sobelow.MetaLog.delete_raw(var, template_path)
            t_name = String.replace_prefix(Path.expand(template_path, ""), "/", "")
            add_finding(t_name, line_no, filename, fun_name, fun, var, :high, finding)
          end
        end)

        Enum.each(vars, fn var ->
          var = "@#{var}"
          if Enum.member?(raw_vals, var) do
            Sobelow.MetaLog.delete_raw(var, template_path)
            t_name = String.replace_prefix(Path.expand(template_path, ""), "/", "")
            add_finding(t_name, line_no, filename, fun_name, fun, var, :medium, finding)
          end
        end)
      end
    end)
  end

  def parse_render_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns =
      Utils.get_pipe_funs(fun)
      |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
      |> Enum.flat_map(&Utils.get_funs_of_type(&1, :render))

    pipevars =
      pipefuns
      |> Enum.map(&{&1, Utils.parse_render_opts(&1, params, 0)})
      |> List.flatten()

    vars =
      (Utils.get_funs_of_type(fun, :render) -- pipefuns)
      |> Enum.map(&{&1, Utils.parse_render_opts(&1, params, 1)})

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def parse_raw_def(fun) do
    {vars, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 0, :raw)
    {aliased, _, _} = Utils.get_fun_vars_and_meta(fun, 0, :raw, :HTML)

    {vars ++ aliased, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.XSS.details()
  end

  defp add_finding(t_name, line_no, filename, fun_name, fun, var, severity, finding) do
    type = "XSS"

    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          file: filename,
          function: "#{fun_name}:#{line_no}",
          variable: "@#{var}",
          template: "#{t_name}"
        ]

        Sobelow.log_finding(finding, severity)

      "txt" ->
        Sobelow.log_finding(type, severity)

        IO.puts(Utils.finding_header(type, severity))
        IO.puts(Utils.finding_file_metadata(filename, fun_name, line_no))
        IO.puts("Template: #{t_name} - #{var}")
        if Sobelow.get_env(:verbose), do: Utils.print_code(fun, finding)
        IO.puts(Utils.finding_break())

      "compact" ->
        Utils.log_compact_finding(type, filename, line_no, severity)

      _ ->
        Sobelow.log_finding(type, severity)
    end
  end
end
