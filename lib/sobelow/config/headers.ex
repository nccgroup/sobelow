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
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Missing Secure Browser Headers"

  def run(router, _) do
    Utils.get_pipelines(router)
    |> Enum.each(&is_vuln_pipeline?(&1, router))
  end

  defp is_vuln_pipeline?(pipeline, router) do
    if Utils.is_vuln_pipeline?(pipeline, :headers) do
      add_finding(pipeline, router)
    end
  end

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline, file) do
    custom_header = "Pipeline: #{pipeline_name}:#{line_no}"

    file = file |> String.replace("//", "/")
    context = Utils.get_context(file, line_no)

    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          file: file,
          pipeline: "#{pipeline_name}",
          line: "#{line_no}",
          context: context
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(@finding_type, :high)

        Utils.print_custom_finding_metadata(
          pipeline,
          :put_secure_browser_headers,
          :high,
          @finding_type,
          [custom_header]
        )

      "compact" ->
        Utils.log_compact_finding(@finding_type, :high)

      _ ->
        Sobelow.log_finding(@finding_type, :high)
    end
  end
end
