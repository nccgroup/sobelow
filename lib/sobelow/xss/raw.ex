defmodule Sobelow.XSS.Raw do
  alias Sobelow.{Parse, Print, Utils}
  use Sobelow.Finding
  @finding_type "XSS.Raw: XSS"

  def run(fun, meta_file, _, nil) do
    severity = if meta_file.is_controller?, do: false, else: :low

    {vars, params, {fun_name, line_no}} = parse_raw_def(fun)

    Enum.each(vars, fn {finding, var} ->
      Print.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Print.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  def run(fun, meta_file, web_root, controller) do
    {vars, _, {fun_name, line_no}} = parse_render_def(fun)
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
        raw_vals = Parse.get_template_vars(raw_funs.raw)

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
    {params, {fun_name, line_no}} = Parse.get_fun_declaration(fun)

    pipefuns =
      Parse.get_pipe_funs(fun)
      |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
      |> Enum.flat_map(&Parse.get_funs_of_type(&1, :render))

    pipevars =
      pipefuns
      |> Enum.map(&{&1, Parse.parse_render_opts(&1, params, 0)})
      |> List.flatten()

    vars =
      (Parse.get_funs_of_type(fun, :render) -- pipefuns)
      |> Enum.map(&{&1, Parse.parse_render_opts(&1, params, 1)})

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def parse_raw_def(fun) do
    {vars, params, {fun_name, line_no}} = Parse.get_fun_vars_and_meta(fun, 0, :raw)
    {aliased, _, _} = Parse.get_fun_vars_and_meta(fun, 0, :raw, :HTML)

    {vars ++ aliased, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.XSS.details()
  end

  defp add_finding(t_name, line_no, filename, fun_name, fun, var, severity, finding) do
    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          file: filename,
          variable: "#{var}",
          template: "#{t_name}"
        ]

        Sobelow.log_finding(finding, severity)

      "txt" ->
        Sobelow.log_finding(@finding_type, severity)

        Print.print_custom_finding_metadata(fun, finding, severity, @finding_type, [
          Print.finding_file_name(filename),
          Print.finding_line(finding),
          Print.finding_fun_metadata(fun_name, line_no),
          "Template: #{t_name} - #{var}"
        ])

      "compact" ->
        Print.log_compact_finding(line_no, @finding_type, filename, severity)

      _ ->
        Sobelow.log_finding(@finding_type, severity)
    end
  end
end
