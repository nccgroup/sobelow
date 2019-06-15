defmodule Sobelow.Config.CSRF do
  @moduledoc """
  # Cross-Site Request Forgery

  In a Cross-Site Request Forgery (CSRF) attack, an untrusted
  application can cause a user's browser to submit requests or perform
  actions on the user's behalf.

  Read more about CSRF here:
  https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

  Cross-Site Request Forgery is flagged by `sobelow` when
  a pipeline fetches a session, but does not implement the
  `:protect_from_forgery` plug.

  CSRF checks can be ignored with the following command:

      $ mix sobelow -i Config.CSRF
  """
  alias Sobelow.{Config, Parse, Print, Utils}
  use Sobelow.Finding
  @finding_type "Config.CSRF: Missing CSRF Protections"

  def run(router, _) do
    Config.get_pipelines(router)
    |> Enum.each(fn pipeline ->
      if is_vuln_pipeline?(pipeline) do
        add_finding(pipeline, router)
      end
    end)
  end

  defp is_vuln_pipeline?(pipeline) do
    Config.is_vuln_pipeline?(pipeline, :csrf)
  end

  defp add_finding({:pipeline, _, [pipeline_name, _]} = pipeline, router) do
    line_no = Parse.get_fun_line(pipeline)
    router_path = Utils.normalize_path(router)
    file_header = "File: #{router_path}"
    pipeline_header = "Pipeline: #{pipeline_name}"
    line_header = "Line: #{line_no}"

    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          file: router_path,
          pipeline: pipeline_name,
          line: line_no
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(@finding_type, :high)

        Print.print_custom_finding_metadata(
          pipeline,
          pipeline_name,
          :high,
          @finding_type,
          [file_header, pipeline_header, line_header]
        )

      "compact" ->
        Print.log_compact_finding(@finding_type, :high)

      _ ->
        Sobelow.log_finding(@finding_type, :high)
    end
  end
end
