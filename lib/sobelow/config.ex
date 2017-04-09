defmodule Sobelow.Config do
  alias Sobelow.Utils

  def hardcoded_secrets do
    prod_path = "config/prod.exs"
    prod_secret_path = "config/prod.secret.exs"

    IO.puts IO.ANSI.cyan_background() <>
      IO.ANSI.black() <>
      "Searching for Hardcoded Secrets" <>
      IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"

    get_secrets_by_file(:secret_key_base, prod_path)
    |> enumerate_secrets(prod_path)

    get_secrets_by_file(:secret_key_base, prod_secret_path)
    |> enumerate_secrets(prod_secret_path)

    get_secrets_by_file(:password, prod_path)
    |> enumerate_secrets(prod_path)

    get_secrets_by_file(:password, prod_secret_path)
    |> enumerate_secrets(prod_secret_path)
  end

  defp get_secrets_by_file(secret, file) do
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

  defp print_finding(file, line_no, val) do
    IO.puts IO.ANSI.red() <> "Hardcoded Secret discovered - Highly Likely" <> IO.ANSI.reset()
    IO.puts "File: #{file} - line #{line_no}"
    IO.puts "Value: #{val}"
    IO.puts "\n-----------------------------------------------\n"
  end
end