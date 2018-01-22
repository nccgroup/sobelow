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

  def run(dir_path, configs) do
    Enum.each(configs, fn conf ->
      path = dir_path <> conf

      if conf != "config.exs" do
        Config.get_configs_by_file(:secret_key_base, path)
        |> enumerate_secrets(path)
      end

      Utils.get_fuzzy_configs("password", path)
      |> enumerate_fuzzy_secrets(path)

      Utils.get_fuzzy_configs("secret", path)
      |> enumerate_fuzzy_secrets(path)
    end)
  end

  defp enumerate_secrets(secrets, file) do
    file = Path.expand(file, "") |> String.replace_prefix("/", "")

    Enum.each(secrets, fn {{_, [line: lineno], _} = fun, key, val} ->
      if is_binary(val) && String.length(val) > 0 && !is_env_var?(val) do
        add_finding(file, lineno, fun, key, val)
      end
    end)
  end

  defp enumerate_fuzzy_secrets(secrets, file) do
    file = Path.expand(file, "") |> String.replace_prefix("/", "")

    Enum.each(secrets, fn {{_, [line: lineno], _} = fun, vals} ->
      Enum.each(vals, fn {k, v} ->
        if is_binary(v) && String.length(v) > 0 && !is_env_var?(v) do
          add_finding(file, lineno, fun, k, v)
        end
      end)
    end)
  end

  def is_env_var?("${" <> rest) do
    String.ends_with?(rest, "}")
  end

  def is_env_var?(_), do: false

  defp add_finding(file, line_no, fun, key, _val) do
    type = "Hardcoded Secret"

    case Sobelow.get_env(:format) do
      "json" ->
        finding = [type: type]
        Sobelow.log_finding(finding, :high)

      "txt" ->
        IO.puts(IO.ANSI.red() <> type <> " - High Confidence" <> IO.ANSI.reset())
        IO.puts("File: #{file} - line #{line_no}")
        IO.puts("Type: #{key}")
        if Sobelow.get_env(:verbose), do: Utils.print_code(fun, :highlight_all)
        IO.puts("\n-----------------------------------------------\n")

      "compact" ->
        Utils.log_compact_finding(type, file, line_no, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end
end
