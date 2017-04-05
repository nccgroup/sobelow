defmodule Sobelow.Config do
  alias Sobelow.Utils

  def run do
    path = "lib/hexpm/web/router.ex"
    Utils.get_routes(path)
#    hardcoded_secrets()
  end

  def hardcoded_secrets do
    secrets = Utils.get_configs(:secret_key_base, "config/config.exs")

    Enum.each secrets, fn {{_, [line: lineno], _}, val} ->
      if is_binary(val) do
        IO.puts("Hardcoded secret on line #{lineno} of config.exs: #{val}")
      end
    end

    passwords = Utils.get_configs(:password, "config/dev.exs")

    Enum.each passwords, fn {{_, [line: lineno], _}, val} ->
      if is_binary(val) do
        IO.puts("Hardcoded password on line #{lineno} of dev.exs: #{val}\n")
      end
    end
  end
end