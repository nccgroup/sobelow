defmodule Sobelow.Config.HTTPS do
  alias Sobelow.Config
  alias Sobelow.Utils

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
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(:hsts) do
    IO.puts IO.ANSI.yellow() <> "HSTS Not Enabled - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"
  end
end