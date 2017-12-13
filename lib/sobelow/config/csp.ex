defmodule Sobelow.Config.CSP do
  @moduledoc """
  # Missing Content-Security-Policy

  Content-Security-Policy is an HTTP header that helps mitigate...

  Read more about CSP here:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

  Missing Content-Security-Policy is flagged by `sobelow` when
  a pipeline implements the `:put_secure_browser_headers` plug,
  but does not provide a Content-Security-Policy header in the
  custom headers map.

  Documentation on the `put_secure_browser_headers` plug function
  can be found here:
  https://hexdocs.pm/phoenix/Phoenix.Controller.html#put_secure_browser_headers/2

  Content-Security-Policy checks can be ignored with the following command:

      $ mix sobelow -i Config.CSP
  """
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Missing Content-Security-Policy"

  def run(router, _) do
    Utils.get_pipelines(router)
    |> Enum.each(&check_vuln_pipeline/1)
  end

  defp check_vuln_pipeline({:pipeline, _, [_name, [do: block]]} = pipeline) do
    {vuln?, conf} =
      Utils.get_plug_list(block)
      |> Enum.find(&is_header_plug?/1)
      |> missing_csp_status()

    if vuln?, do: add_finding(pipeline, conf)
  end

  defp is_header_plug?({:plug, _, [:put_secure_browser_headers]}), do: true
  defp is_header_plug?({:plug, _, [:put_secure_browser_headers, _]}), do: true
  defp is_header_plug?(_), do: false

  defp missing_csp_status({:plug, _, [:put_secure_browser_headers]}), do: {true, :high}
  defp missing_csp_status({:plug, _, [:put_secure_browser_headers, {:%{}, _, opts}]}) do
    has_csp? =
      Enum.any?(opts, fn
        {key, _} when is_binary(key) ->
          String.downcase(key) == "content-security-policy"
        _ ->
          false
      end)

    {!has_csp?, :high}
  end
  defp missing_csp_status({:plug, _, [:put_secure_browser_headers, _]}), do: {true, :low}
  defp missing_csp_status(_), do: {false, :high}

  defp add_finding({:pipeline, [line: line_no], [pipeline_name, _]} = pipeline, conf) do
    custom_header = "Pipeline: #{pipeline_name}:#{line_no}"
    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          pipeline: "#{pipeline_name}:#{line_no}"
        ]
        Sobelow.log_finding(finding, conf)
      "txt" ->
        Sobelow.log_finding(@finding_type, conf)
        Utils.print_custom_finding_metadata(pipeline, :put_secure_browser_headers,
                                            conf, @finding_type, [custom_header])
      "compact" ->
        Utils.log_compact_finding(@finding_type, conf)
      _ ->
        Sobelow.log_finding(@finding_type, conf)
    end
  end
end