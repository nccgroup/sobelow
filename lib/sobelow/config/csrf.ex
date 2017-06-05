defmodule Sobelow.Config.CSRF do
  @moduledoc """
  # Cross-Site Request Forgery

  In a Cross-Site Request Forgery (CSRF) attack, an untrusted
  application can cause a user's browser to submit requests or perform
  actions on the user's behalf.

  Read more about CSRF here:
  https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

  Cross-Site Request Forgery is flagged by `sobelow` when
  a pipeline accepts "html" requests, but does not implement
  the `:protect_from_forgery` plug.

  CSRF checks can be ignored with the following command:

      $ mix sobelow -i Config.CSRF
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(router) do
    Utils.get_pipelines(router)
    |> Enum.each(&is_vuln_pipeline/1)
  end

  defp is_vuln_pipeline(pipeline) do
    if Utils.is_vuln_pipeline(pipeline) do
      Sobelow.log_finding("CSRF", :high)
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
