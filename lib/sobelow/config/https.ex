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
  alias Sobelow.{Config, Print, Utils}
  use Sobelow.Finding
  @finding_type "Config.HTTPS: HTTPS Not Enabled"

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
    filename = Utils.normalize_path(file)
    reason = "HTTPS configuration details could not be found in `prod.exs`."

    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          file: filename,
          line: 0
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(@finding_type, :high)

        Print.print_custom_finding_metadata(nil, reason, :high, @finding_type, [])

      "compact" ->
        Print.log_compact_finding(@finding_type, :high)

      _ ->
        Sobelow.log_finding(@finding_type, :high)
    end
  end
end
