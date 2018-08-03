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

  def run(router, _) do
    Utils.get_pipelines(router)
    |> Enum.each(&is_vuln_pipeline?(&1, router))
  end

  defp is_vuln_pipeline?(pipeline, router) do
    if Utils.is_vuln_pipeline?(pipeline, :csrf) do
      add_finding(pipeline, router)
    end
  end

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline, file) do
    type = "Missing CSRF Protections"

    file = file |> String.replace("//", "/")
    context = Utils.get_context(file, line_no)

    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          file: file,
          pipeline: "#{pipeline_name}",
          line: "#{line_no}",
          context: context
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)
        IO.puts(IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset())
        IO.puts("Pipeline: #{pipeline_name}:#{line_no}")
        if Sobelow.get_env(:verbose), do: Utils.print_code(pipeline, pipeline_name)
        IO.puts("\n-----------------------------------------------\n")

      "compact" ->
        Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end
end
