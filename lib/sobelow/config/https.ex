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
    Config.get_configs_by_file(:https, path)
    |> handle_https()
  end

  defp handle_https(opts) do
    if length(opts) === 0 do
      add_finding()
    end
  end

  defp add_finding() do
    type = "HTTPS Not Enabled"
    case Sobelow.format() do
      "json" ->
        finding = [type: type]
        Sobelow.log_finding(finding, :high)
      _ ->
        Sobelow.log_finding(type, :high)

        IO.puts IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset()
        if Sobelow.get_env(:with_code), do: print_info()
        IO.puts "\n-----------------------------------------------\n"
    end
  end

  defp print_info() do
    IO.puts "\nHTTPS configuration details could not be found in `prod.exs`."
  end
end