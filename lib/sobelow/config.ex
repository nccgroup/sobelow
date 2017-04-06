defmodule Sobelow.Config do
  alias Sobelow.Utils

  def hardcoded_secrets do
    prod_path = "config/prod.exs"
    prod_secret_path = "config/prod.secret.exs"

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
      if is_binary(val) do
        IO.puts("Hardcoded secret on line #{lineno} of #{file}: #{val}")
      end
    end
  end
end