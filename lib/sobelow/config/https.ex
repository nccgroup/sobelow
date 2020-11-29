defmodule Sobelow.Config.HTTPS do
  @moduledoc """
  # HTTPS

  Without HTTPS, attackers in a priveleged network position can
  intercept and modify traffic.

  Sobelow detects missing HTTPS by checking the prod
  configuration.

  HTTPS checks can be ignored with the following command:

      $ mix sobelow -i Config.HTTPS
  """
  alias Sobelow.Config

  @uid 9
  @finding_type "Config.HTTPS: HTTPS Not Enabled"

  use Sobelow.Finding

  def run(dir_path, configs) do
    path = dir_path <> "prod.exs"

    if File.exists?(path) && Enum.member?(configs, "prod.exs") do
      https = Config.get_configs_by_file(:https, path)

      (Config.get_configs_by_file(:force_ssl, path) ++ https)
      |> handle_https(path)
    end
  end

  defp handle_https(opts, path) do
    if length(opts) === 0 do
      add_finding(path)
    end
  end

  defp add_finding(file) do
    reason = "HTTPS configuration details could not be found in `prod.exs`."

    finding =
      %Finding{
        type: @finding_type,
        filename: Utils.normalize_path(file),
        fun_source: nil,
        vuln_source: reason,
        vuln_line_no: 0,
        vuln_col_no: 0,
        confidence: :high
      }
      |> Finding.fetch_fingerprint()

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

        Print.print_custom_finding_metadata(finding, [])

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
