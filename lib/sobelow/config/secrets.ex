defmodule Sobelow.Config.Secrets do
  @moduledoc """
  # Hard-coded Secrets

  In the event of a source-code disclosure via file read
  vulnerability, accidental commit, etc, hard-coded secrets
  may be exposed to an attacker. This may result in
  database access, cookie forgery, and other issues.

  Sobelow detects missing hard-coded secrets by checking the prod
  configuration.

  Hard-coded secrets checks can be ignored with the following command:

      $ mix sobelow -i Config.Secrets
  """
  alias Sobelow.Config
  alias Sobelow.Utils
  use Sobelow.Finding
  @prod_path "config/prod.exs"
  @prod_secret_path "config/prod.secret.exs"

  def run(root) do
    Config.get_configs_by_file(:secret_key_base, root <> @prod_path)
    |> enumerate_secrets(root <> @prod_path)

    Config.get_configs_by_file(:secret_key_base, root <> @prod_secret_path)
    |> enumerate_secrets(root <> @prod_secret_path)

    Config.get_configs_by_file(:password, root <> @prod_path)
    |> enumerate_secrets(root <> @prod_path)

    Config.get_configs_by_file(:password, root <> @prod_secret_path)
    |> enumerate_secrets(root <> @prod_secret_path)
  end

  defp enumerate_secrets(secrets, file) do
    file = Path.expand(file, "")
    Enum.each secrets, fn {{_, [line: lineno], _} = fun, key, val} ->
      if is_binary(val) && String.length(val) > 0 && !is_env_var?(val) do
        add_finding(file, lineno, fun, key, val)
      end
    end
  end

  def is_env_var?("${" <> rest) do
    String.ends_with?(rest, "}")
  end
  def is_env_var?(_), do: false

  defp add_finding(file, line_no, fun, key, val) do
    type = "Hardcoded Secret"
    case Sobelow.get_env(:format) do
      "json" ->
        finding = """
        {
            "type": "#{type}"
        }
        """
        Sobelow.log_finding(finding, :high)
      _ ->
        IO.puts IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset()
        IO.puts "File: #{file} - line #{line_no}"
        IO.puts "Type: #{key}"
        if Sobelow.get_env(:with_code), do: Utils.print_code(fun, :highlight_all)
        IO.puts "\n-----------------------------------------------\n"
    end
  end
end