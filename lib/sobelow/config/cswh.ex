defmodule Sobelow.Config.CSWH do
  @moduledoc """
  # Cross-Site Websocket Hijacking

  Websocket connections are not bound by the same-origin policy.
  Connections that do not validate the origin may leak information
  to an attacker.

  More information can be found here: https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html

  Cross-Site Websocket Hijacking checks can be disabled with
  the following command:

      $ mix sobelow -i Config.CSWH
  """
  @uid 6
  @finding_type "Config.CSWH: Cross-Site Websocket Hijacking"

  use Sobelow.Finding

  def run(endpoint) do
    Parse.ast(endpoint)
    |> Parse.get_funs_of_type(:socket)
    |> handle_sockets(endpoint)
  end

  defp handle_sockets(sockets, endpoint) do
    Enum.each(sockets, fn socket ->
      check_socket(socket)
      |> add_finding(socket, endpoint)
    end)
  end

  def check_socket({_, _, [_, _, options]}) do
    check_socket_options(options)
  end

  def check_socket(_), do: {false, :high}

  defp check_socket_options([{:websocket, options} | _]) when is_list(options) do
    case options[:check_origin] do
      false -> {true, :high}
      true -> {false, :high}
      nil -> {false, :high}
      _ -> {true, :low}
    end
  end

  defp check_socket_options([_ | t]), do: check_socket_options(t)
  defp check_socket_options([]), do: {false, :high}

  defp add_finding(nil, _, _), do: nil
  defp add_finding({false, _}, _, _), do: nil

  defp add_finding({true, confidence}, socket, endpoint) do
    finding = Finding.init(@finding_type, Utils.normalize_path(endpoint), confidence)

    finding =
      %{
        finding
        | vuln_source: :highlight_all,
          vuln_line_no: Parse.get_fun_line(socket),
          vuln_col_no: Parse.get_fun_column(socket),
          fun_source: socket
      }
      |> Finding.fetch_fingerprint()

    file_header = "File: #{finding.filename}"
    line_header = "Line: #{finding.vuln_line_no}"

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(
          finding,
          [file_header, line_header]
        )

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
