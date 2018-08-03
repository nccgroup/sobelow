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
    type = "HTTPS Not Enabled"
    file = file |> String.replace("//", "/")

    case Sobelow.format() do
      "json" ->
        finding = [type: type, file: file]
        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)

        IO.puts(IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset())
        if Sobelow.get_env(:verbose), do: print_info()
        IO.puts("\n-----------------------------------------------\n")

      "compact" ->
        Sobelow.Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end

  defp print_info() do
    IO.puts("\nHTTPS configuration details could not be found in `prod.exs`.")
  end
end
