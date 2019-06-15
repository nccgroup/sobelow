defmodule Sobelow.Config.Headers do
  @moduledoc """
  # Missing Secure HTTP Headers

  By default, Phoenix HTTP responses contain a number of
  secure HTTP headers that attempt to mitigate XSS,
  click-jacking, and content-sniffing attacks.

  Missing Secure HTTP Headers is flagged by `sobelow` when
  a pipeline accepts "html" requests, but does not implement
  the `:put_secure_browser_headers` plug.

  Secure Headers checks can be ignored with the following
  command:

      $ mix sobelow -i Config.Headers
  """
  alias Sobelow.{Config, Print, Utils}
  use Sobelow.Finding
  @finding_type "Config.Headers: Missing Secure Browser Headers"

  def run(router, _) do
    Config.get_pipelines(router)
    |> Enum.each(fn pipeline ->
      if is_vuln_pipeline?(pipeline) do
        add_finding(pipeline, router)
      end
    end)
  end

  defp is_vuln_pipeline?(pipeline) do
    Config.is_vuln_pipeline?(pipeline, :headers)
  end

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline, router) do
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
