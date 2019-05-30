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
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(dir_path, configs) do
    path = dir_path <> "prod.exs"

    if File.exists?(path) && Enum.member?(configs, "prod.exs") do
      https = Config.get_configs_by_file(:https, path)

      (Config.get_configs_by_file(:force_ssl, path) ++ https)
      |> handle_https()
    end
  end

  defp handle_https(opts) do
    if length(opts) === 0 do
      add_finding()
    end
  end

  defp add_finding() do
    type = "Config.HTTPS: HTTPS Not Enabled"
    reason = "HTTPS configuration details could not be found in `prod.exs`."

    case Sobelow.format() do
      "json" ->
        finding = [type: type]
        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)

        Utils.print_custom_finding_metadata(nil, reason, :high, type, [])

      "compact" ->
        Sobelow.Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end
end
