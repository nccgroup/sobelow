defmodule Sobelow.Config.HTTPS do
  @moduledoc """
  # HTTPS

  Without HTTPS, attackers in a privileged network position can
  intercept and modify traffic.

  Sobelow detects missing HTTPS by checking the prod
  configuration.

  HTTPS checks can be ignored with the following command:

      $ mix sobelow -i Config.HTTPS
  """
  alias Sobelow.Config

  @uid 9
  @finding_type "Config.HTTPS: HTTPS Not Enabled"
  @files_to_check ["prod.exs", "runtime.exs"]

  use Sobelow.Finding

  def run(dir_path, configs, files_to_check \\ @files_to_check) do
    configs_in_files = configs_in_files(dir_path, configs, files_to_check)

    if !Enum.empty?(configs_in_files) && Enum.all?(configs_in_files, &https_config_missing?/1) do
      Enum.each(configs_in_files, fn {path, _} ->
        add_finding(path)
      end)
    end
  end

  defp configs_in_files(dir_path, configs, files) do
    files
    |> Enum.map(fn file_path ->
      path = dir_path <> file_path
      exists = File.exists?(path) && Enum.member?(configs, file_path)
      {path, exists}
    end)
    |> Enum.filter(fn {_path, exists} -> exists end)
    |> Enum.map(fn {path, _exists} ->
      https = Config.get_configs_by_file(:https, path)
      {path, Config.get_configs_by_file(:force_ssl, path) ++ https}
    end)
  end

  defp https_config_missing?({_path, opts}) do
    Enum.empty?(opts)
  end

  defp add_finding(file) do
    reason = "HTTPS configuration details could not be found in `prod.exs` nor `runtime.exs`."

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

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
