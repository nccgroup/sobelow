defmodule Sobelow.XSS.Raw do
  @uid 30
  @finding_type "XSS.Raw: XSS"

  use Sobelow.Finding

  def run(fun, meta_file, _, nil) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_raw_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def run(fun, meta_file, _web_root, controller) do
    {vars, _, {fun_name, line_no}} = parse_render_def(fun)
    filename = meta_file.filename
    templates = Sobelow.MetaLog.get_templates()

    tmp_template_root =
      templates
      |> Map.keys()
      |> List.first()

    template_root =
      case tmp_template_root do
        nil -> ""
        path -> String.split(path, "/templates/") |> List.first()
      end

    Enum.each(vars, fn {finding, {template, ref_vars, vars}} ->
      template =
        cond do
          is_atom(template) -> Atom.to_string(template) <> ".html"
          is_binary(template) -> template
          true -> ""
        end

      template_path =
        (template_root <> "/templates/" <> controller <> "/" <> template <> ".eex")
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
    Parse.get_fun_vars_and_meta(fun, 0, :raw, :HTML)
  end

  def details() do
    Sobelow.XSS.details()
  end

  defp add_finding(t_name, line_no, filename, fun_name, fun, var, severity, finding) do
    finding =
      %Finding{
        type: @finding_type,
        filename: filename,
        fun_source: fun,
        vuln_source: finding,
        vuln_variable: var,
        vuln_line_no: Parse.get_fun_line(finding),
        vuln_col_no: Parse.get_fun_column(finding),
        confidence: severity
      }
      |> Finding.fetch_fingerprint()

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          variable: "#{finding.vuln_variable}",
          template: "#{t_name}",
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(finding, [
          Print.finding_file_name(filename),
          Print.finding_line(finding.vuln_source),
          Print.finding_fun_metadata(fun_name, line_no),
          "Template: #{t_name} - #{var}"
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
