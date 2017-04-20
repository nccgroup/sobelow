defmodule Sobelow.Config.CSRF do
  @moduledoc """
  Cross-Site Request Forgery (CSRF) is flagged by `sobelow` when
  a pipeline accepts "html" requests, but does not implement
  the `:protect_from_forgery` plug.

  Read more about CSRF here:
  https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
  """
  alias Sobelow.Utils

  def run(root) do
    Utils.get_pipelines(root <> "web/" <> "router.ex")
    |> Enum.each(&is_vuln_pipeline/1)
  end

  defp is_vuln_pipeline(pipeline) do
    if Utils.is_vuln_pipeline(pipeline) do
      print_finding(pipeline)
    end
  end

  defp print_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline) do
    IO.puts IO.ANSI.red() <> "Missing CSRF Protections - High Confidence" <> IO.ANSI.reset()
    IO.puts "Pipeline: #{pipeline_name}:#{line_no}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(pipeline, pipeline_name)
    IO.puts "\n-----------------------------------------------\n"
  end
end