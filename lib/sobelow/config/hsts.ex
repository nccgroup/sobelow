defmodule Sobelow.Config.HSTS do
  @moduledoc """
  # HSTS

  The HTTP Strict Transport Security (HSTS) header helps
  defend against man-in-the-middle attacks by preventing
  unencrypted connections.

  HSTS checks can be ignored with the following command:

      $ mix sobelow -i Config.HSTS
  """
  alias Sobelow.Config

  @uid 8
  @finding_type "Config.HSTS: HSTS Not Enabled"

  use Sobelow.Finding

  def run(dir_path, configs) do
    Enum.each(configs, fn conf ->
      path = dir_path <> conf

      Config.get_configs_by_file(:https, path)
      |> handle_https(path)
    end)
  end

  defp handle_https(opts, file) do
    # If HTTPS configs were found in any config file and there
    # are no accompanying HSTS configs, add an HSTS finding.
    if length(opts) > 0 && length(Config.get_configs(:force_ssl, file)) === 0 do
      add_finding(file)
    end
  end

  defp add_finding(file) do
    reason = "HSTS configuration details could not be found in `#{Path.basename(file)}`."

    finding =
      %Finding{
        type: @finding_type,
        filename: Utils.normalize_path(file),
        fun_source: nil,
        vuln_source: reason,
        vuln_line_no: 0,
        vuln_col_no: 0,
        confidence: :medium
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
