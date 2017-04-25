defmodule Sobelow.Config.HTTPS do
  @moduledoc """
  # HTTPS

  Without HTTPS, attackers in a priveleged network position can
  intercept and modify traffic. The HTTP Strict Transport Security
  (HSTS) header helps defend against man-in-the-middle attacks by
  preventing unencrypted connections.

  Sobelow detects missing HTTPS/HSTS by checking the prod
  configuration.

  HTTPS/HSTS checks can be ignored with the following command:

      $ mix sobelow -i Config.HTTPS
  """
  alias Sobelow.Config
  alias Sobelow.Utils
  use Sobelow.Finding

  @prod_path "config/prod.exs"

  def run(root) do
    Config.get_configs_by_file(:https, root <> @prod_path)
    |> handle_https(root <> @prod_path)
  end

  defp handle_https(opts, file) do
    if length(opts) === 0 do
      print_finding(:https)
    else
      if length(Utils.get_configs(:force_ssl, file)) === 0 do
        print_finding(:hsts)
      end
    end
  end

  defp print_finding(:https) do
    IO.puts IO.ANSI.red() <> "HTTPS Not Enabled - High Confidence" <> IO.ANSI.reset()
    if Sobelow.get_env(:with_code), do: print_info("HTTPS")
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(:hsts) do
    IO.puts IO.ANSI.yellow() <> "HSTS Not Enabled - Medium Confidence" <> IO.ANSI.reset()
    if Sobelow.get_env(:with_code), do: print_info("HSTS")
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_info(type) do
    IO.puts "\n#{type} configuration details could not be found in `prod.exs` or `prod.secret.exs`."
  end
end