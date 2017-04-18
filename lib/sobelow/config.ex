defmodule Sobelow.Config do
  alias Sobelow.Utils
  @prod_path "config/prod.exs"
  @prod_secret_path "config/prod.secret.exs"

  def fetch(root) do
    Utils.get_pipelines(root <> "web/" <> "router.ex")
    |> Enum.each(&is_vuln_pipeline/1)

    get_configs_by_file(:secret_key_base, root <> @prod_path)
    |> enumerate_secrets(root <> @prod_path)

    get_configs_by_file(:secret_key_base, root <> @prod_secret_path)
    |> enumerate_secrets(root <> @prod_secret_path)

    get_configs_by_file(:password, root <> @prod_path)
    |> enumerate_secrets(root <> @prod_path)

    get_configs_by_file(:password, root <> @prod_secret_path)
    |> enumerate_secrets(root <> @prod_secret_path)

    get_configs_by_file(:https, root <> @prod_path)
    |> handle_https(root <> @prod_path)
  end

  defp is_vuln_pipeline(pipeline) do
    if Utils.is_vuln_pipeline(pipeline) do
      print_finding(pipeline)
    end
  end

  defp get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end

  defp enumerate_secrets(secrets, file) do
    file = Path.expand(file, "")
    Enum.each secrets, fn {{_, [line: lineno], _} = fun, key, val} ->
      if is_binary(val) && String.length(val) > 0 do
        print_finding(file, lineno, fun, key, val)
      end
    end
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

  defp print_finding({:pipeline, [line: line_no], [pipeline, _]}) do
    IO.puts IO.ANSI.red() <> "Missing CSRF Protections - High Confidence" <> IO.ANSI.reset()
    IO.puts "Pipeline: #{pipeline}:#{line_no}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(:https) do
    IO.puts IO.ANSI.red() <> "HTTPS Not Enabled - High Confidence" <> IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(:hsts) do
    IO.puts IO.ANSI.yellow() <> "HSTS Not Enabled - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(file, line_no, fun, key, val) do
    IO.puts IO.ANSI.red() <> "Hardcoded Secret - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{file} - line #{line_no}"
    IO.puts "Type: #{key}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, :highlight_all)
    IO.puts "\n-----------------------------------------------\n"
  end
end