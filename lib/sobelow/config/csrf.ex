defmodule Sobelow.Config.CSRF do
  @moduledoc """
  # Cross-Site Request Forgery

  In a Cross-Site Request Forgery (CSRF) attack, an untrusted
  application can cause a user's browser to submit requests or perform
  actions on the user's behalf.

  Read more about CSRF here:
  https://owasp.org/www-community/attacks/csrf

  Cross-Site Request Forgery is flagged by `sobelow` when
  a pipeline fetches a session, but does not implement the
  `:protect_from_forgery` plug.

  CSRF checks can be ignored with the following command:

      $ mix sobelow -i Config.CSRF
  """
  alias Sobelow.Config

  @uid 5
  @finding_type "Config.CSRF: Missing CSRF Protections"

  use Sobelow.Finding

  def run(router) do
    finding = Finding.init(@finding_type, Utils.normalize_path(router))

    Config.get_pipelines(router)
    |> Stream.filter(&is_vuln_pipeline?/1)
    |> Enum.each(&add_finding(&1, finding))
  end

  defp is_vuln_pipeline?(pipeline) do
    Config.is_vuln_pipeline?(pipeline, :csrf)
  end

  defp add_finding({:pipeline, _, [pipeline_name, _]} = pipeline, finding) do
    %{
      finding
      | vuln_source: pipeline_name,
        vuln_line_no: Parse.get_fun_line(pipeline),
        vuln_col_no: Parse.get_fun_column(pipeline),
        fun_source: pipeline,
        fun_name: pipeline_name,
        confidence: :high
    }
    |> add_finding()
  end

  defp add_finding(%Finding{} = finding) do
    finding = Finding.fetch_fingerprint(finding)
    file_header = "File: #{finding.filename}"
    pipeline_header = "Pipeline: #{finding.fun_name}"
    line_header = "Line: #{finding.vuln_line_no}"

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          pipeline: finding.fun_name,
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(
          finding,
          [file_header, pipeline_header, line_header]
        )

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
