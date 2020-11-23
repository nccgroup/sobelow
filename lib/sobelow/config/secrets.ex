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

  @uid 10
  @finding_type "Config.Secrets: Hardcoded Secret"

  use Sobelow.Finding

  def run(dir_path, configs) do
    Enum.each(configs, fn conf ->
      path = dir_path <> conf

      if conf != "config.exs" do
        Config.get_configs_by_file(:secret_key_base, path)
        |> enumerate_secrets(path)
      end

      Config.get_fuzzy_configs("password", path)
      |> enumerate_fuzzy_secrets(path)

      Config.get_fuzzy_configs("secret", path)
      |> enumerate_fuzzy_secrets(path)
    end)
  end

  defp enumerate_secrets(secrets, file) do
    Enum.each(secrets, fn {fun, key, val} ->
      if is_binary(val) && String.length(val) > 0 && !is_env_var?(val) do
        add_finding(file, Parse.get_fun_line(fun), fun, key, val)
      end
    end)
  end

  defp enumerate_fuzzy_secrets(secrets, file) do
    Enum.each(secrets, fn {fun, vals} ->
      Enum.each(vals, fn {k, v} ->
        if is_binary(v) && String.length(v) > 0 && !is_env_var?(v) do
          add_finding(file, Parse.get_fun_line(fun), fun, k, v)
        end
      end)
    end)
  end

  def is_env_var?("${" <> rest) do
    String.ends_with?(rest, "}")
  end

  def is_env_var?(_), do: false

  defp add_finding(file, line_no, fun, key, val) do
    {vuln_line_no, vuln_line_col} = get_vuln_line(file, line_no, val)

    finding =
      %Finding{
        type: @finding_type,
        filename: Utils.normalize_path(file),
        fun_source: fun,
        vuln_source: :highlight_all,
        vuln_line_no: vuln_line_no,
        vuln_col_no: vuln_line_col,
        confidence: :high
      }
      |> Finding.fetch_fingerprint()

    file_header = "File: #{finding.filename}"
    line_header = "Line: #{finding.vuln_line_no}"
    key_header = "Key: #{key}"

    case Sobelow.get_env(:format) do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          line: finding.vuln_line_no,
          key: key
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(finding, [
          file_header,
          line_header,
          key_header
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  defp get_vuln_line(file, config_line_no, secret) do
    {_, secrets} =
      File.read!(file)
      |> String.replace("\"#{secret}\"", "@sobelow_secret")
      |> Code.string_to_quoted()
      |> Macro.prewalk([], &get_vuln_line/2)

    Enum.find(secrets, config_line_no, &(&1 > config_line_no))
  end

  defp get_vuln_line({:@, _, [{:sobelow_secret, _, _}]} = ast, acc) do
    line_no = Parse.get_fun_line(ast)
    line_col = Parse.get_fun_column(ast)
    {ast, [{line_no, line_col} | acc]}
  end

  defp get_vuln_line(ast, acc), do: {ast, acc}
end
