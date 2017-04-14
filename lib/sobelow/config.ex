defmodule Sobelow.Config do
  alias Sobelow.Utils
  @prod_path "config/prod.exs"
  @prod_secret_path "config/prod.secret.exs"

  def fetch do
    IO.puts IO.ANSI.cyan_background() <>
      IO.ANSI.black() <>
      "Analyzing Configuration" <>
      IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"

    get_configs_by_file(:secret_key_base, @prod_path)
    |> enumerate_secrets(@prod_path)

    get_configs_by_file(:secret_key_base, @prod_secret_path)
    |> enumerate_secrets(@prod_secret_path)

    get_configs_by_file(:password, @prod_path)
    |> enumerate_secrets(@prod_path)

    get_configs_by_file(:password, @prod_secret_path)
    |> enumerate_secrets(@prod_secret_path)

    get_configs_by_file(:https, @prod_path)
    |> handle_https
  end

  defp get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end

  defp enumerate_secrets(secrets, file) do
    Enum.each secrets, fn {{_, [line: lineno], _}, val} ->
      if is_binary(val) && String.length(val) > 0 do
        print_finding(file, lineno, val)
      end
    end
  end

  defp handle_https(opts) do
    if length(opts) === 0 do
      print_finding(:https)
    else
      if length(Utils.get_configs(:force_ssl, @prod_path)) === 0 do
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

  defp print_finding(file, line_no, val) do
    IO.puts IO.ANSI.red() <> "Hardcoded Secret - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{file} - line #{line_no}"
    IO.puts "Value: #{val}"
    IO.puts "\n-----------------------------------------------\n"
  end
end