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
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(router, _) do
    Utils.get_pipelines(router)
    |> Enum.each(fn pipeline ->
      if is_vuln_pipeline?(pipeline) do
        add_finding(pipeline, router)
      end
    end)
  end

  defp is_vuln_pipeline?(pipeline) do
    Utils.is_vuln_pipeline?(pipeline, :csrf)
  end

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline, router) do
    router_path = "File: #{Utils.normalize_path(router)}"
    type = "Config.CSRF: Missing CSRF Protections"

    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          pipeline: "#{pipeline_name}:#{line_no}"
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)

        Utils.print_custom_finding_metadata(
          pipeline,
          pipeline_name,
          :high,
          type,
          [router_path, "Pipeline: #{pipeline_name}:#{line_no}"]
        )

      "compact" ->
        Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end
end
