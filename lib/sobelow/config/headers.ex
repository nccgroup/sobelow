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

  def run(router, _) do
    Utils.get_pipelines(router)
    |> Enum.each(&is_vuln_pipeline?/1)
  end

  defp is_vuln_pipeline?(pipeline) do
    if Utils.is_vuln_pipeline?(pipeline, :headers) do
      add_finding(pipeline)
    end
  end

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline) do
    type = "Missing Secure Browser Headers"
    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          pipeline: "#{pipeline_name}:#{line_no}"
        ]
        Sobelow.log_finding(finding, :high)
      "txt" ->
        Sobelow.log_finding(type, :high)
        IO.puts IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset()
        IO.puts "Pipeline: #{pipeline_name}:#{line_no}"
        if Sobelow.get_env(:verbose), do: Utils.print_code(pipeline, pipeline_name)
        IO.puts "\n-----------------------------------------------\n"
      "compact" ->
        Utils.log_compact_finding(type, :high)
      _ ->
        Sobelow.log_finding(type, :high)
    end
  end
end