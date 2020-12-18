defmodule Sobelow.Print do
  @moduledoc false
  alias Sobelow.{Finding, Parse}

  def add_finding(%Finding{} = finding) do
    finding = Finding.fetch_fingerprint(finding)

    case Sobelow.format() do
      "json" ->
        log_json_finding(finding)

      "txt" ->
        Sobelow.log_finding(finding)
        print_finding_metadata(finding)

      "compact" ->
        log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  def print_finding_metadata(%Finding{} = finding) do
    if Sobelow.loggable?(finding.fingerprint, finding.confidence) do
      do_print_finding_metadata(finding)
    end
  end

  def do_print_finding_metadata(%Finding{} = finding) do
    IO.puts(finding_header(finding.type, finding.confidence))
    IO.puts(finding_file_name(finding.filename))
    IO.puts(finding_line(finding.vuln_line_no))
    maybe_print_finding_fun_metadata(finding.fun_name, finding.fun_line_no)
    IO.puts(finding_variable(finding.vuln_variable))
    maybe_print_code(finding.fun_source, finding.vuln_source)
    IO.puts(finding_break())
  end

  def print_custom_finding_metadata(%Finding{} = finding, headers) do
    if Sobelow.loggable?(finding.fingerprint, finding.confidence) do
      do_print_custom_finding_metadata(finding, headers)
    end
  end

  def do_print_custom_finding_metadata(%Finding{} = finding, headers) do
    IO.puts(finding_header(finding.type, finding.confidence))

    Enum.each(headers, fn header ->
      IO.puts(header)
    end)

    maybe_print_code(finding.fun_source, finding.vuln_source)
    IO.puts(finding_break())
  end

  def log_compact_finding(%Finding{} = finding) do
    details =
      case Sobelow.get_env(:format) do
        "flycheck" -> "#{finding.filename}:#{finding.vuln_line_no}: #{finding.type}"
        "compact" -> "#{finding.type} - #{finding.filename}:#{finding.vuln_line_no}"
      end

    Sobelow.log_finding(%{finding | type: details})
    print_compact_finding(finding, details)
  end

  defp print_compact_finding(finding, details) do
    if Sobelow.loggable?(finding.fingerprint, finding.confidence) do
      do_print_compact_finding(details, finding.confidence)
    end
  end

  defp do_print_compact_finding(details, severity) do
    sev =
      case severity do
        :high -> IO.ANSI.red()
        :medium -> IO.ANSI.yellow()
        :low -> IO.ANSI.green()
      end

    IO.puts("#{sev}[+]#{IO.ANSI.reset()} #{details}")
  end

  def log_json_finding(%Finding{} = finding) do
    json_finding = [
      type: finding.type,
      file: finding.filename,
      line: finding.vuln_line_no,
      variable: finding.vuln_variable
    ]

    Sobelow.log_finding(json_finding, finding)
  end

  def finding_header(type, severity) do
    {color, confidence} = finding_confidence(severity)
    color <> type <> " - #{confidence} Confidence" <> IO.ANSI.reset()
  end

  def finding_file_name(filename) do
    "File: #{filename}"
  end

  def finding_line(line_no) when is_integer(line_no) do
    "Line: #{line_no}"
  end

  def finding_line(finding) do
    "Line: #{Parse.get_fun_line(finding)}"
  end

  def maybe_print_finding_fun_metadata("", _), do: nil

  def maybe_print_finding_fun_metadata(fun_name, line_no),
    do: print_finding_fun_metadata(fun_name, line_no)

  def print_finding_fun_metadata({:unquote, _, _} = fun_name, line_no) do
    print_finding_fun_metadata(Macro.to_string(fun_name), line_no)
  end

  def print_finding_fun_metadata(fun_name, line_no) do
    finding_fun_metadata(fun_name, line_no) |> IO.puts()
  end

  def finding_fun_metadata(fun_name, line_no) do
    "Function: #{fun_name}:#{line_no}"
  end

  def finding_variable({_, _, _} = var) do
    {var, [], []} |> Macro.to_string() |> finding_variable()
  end

  def finding_variable(var) do
    "Variable: #{var}"
  end

  def finding_confidence(severity) do
    case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
  end

  def finding_break() do
    "\n-----------------------------------------------\n"
  end

  def maybe_print_code(fun, finding) do
    if Sobelow.get_env(:verbose), do: print_code(fun, finding)
  end

  def maybe_print_file_path_code(fun, var) do
    if Sobelow.get_env(:verbose), do: print_file_path_code(fun, var)
  end

  def get_sev(params, var) do
    do_get_sev(params, var, :medium, :low)
  end

  def get_sev(params, vars, severity) when is_list(vars) do
    Enum.map(vars, &get_sev(params, &1, severity))
    |> get_highest_sev()
  end

  def get_sev(params, var, false) do
    do_get_sev(params, var, :high, :medium)
  end

  def get_sev(params, var, nil) do
    do_get_sev(params, var, :high, :medium)
  end

  def get_sev(_params, _var, severity) do
    severity
  end

  defp do_get_sev(params, var, high, low) do
    params = ["conn.params" | params]

    case Enum.member?(params, var) do
      true -> high
      false -> low
    end
  end

  defp get_highest_sev(sevs) do
    cond do
      Enum.member?(sevs, :high) -> :high
      Enum.member?(sevs, :medium) -> :medium
      true -> :low
    end
  end

  def print_code(nil, nil), do: nil

  def print_code(nil, out) when is_binary(out) do
    IO.puts("\n")
    IO.puts(out)
  end

  def print_code(fun, :highlight_all) do
    IO.puts("\n")
    IO.puts(IO.ANSI.light_magenta() <> Macro.to_string(fun) <> IO.ANSI.reset())
  end

  def print_code(fun, find) do
    acc = ""

    func_string =
      Macro.to_string(fun, fn ast, string ->
        string = normalize_template_var(ast, string)
        s = print_highlighted(string, ast, find)
        acc <> s
      end)

    IO.puts("\n")
    IO.puts(func_string)
  end

  def print_file_path_code(fun, var) do
    acc = ""

    func_string =
      Macro.to_string(fun, fn ast, string ->
        s =
          case ast do
            {:=, _, [{^var, _, nil} | _]} ->
              maybe_highlight(string, ast, var)

            {{:., _, [{:__aliases__, _, [:Path]}, _]}, _, _} ->
              maybe_highlight(string, ast, var)

            {{:., _, [{:__aliases__, _, [:File]}, _]}, _, _} ->
              maybe_highlight(string, ast, var)

            _ ->
              if is_nil(string), do: "", else: string
          end

        acc <> s
      end)

    IO.puts("\n")
    IO.puts(func_string)
  end

  def print_highlighted(string, ast, find) do
    case find do
      ^ast ->
        IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()

      _ ->
        if is_nil(string), do: "", else: string
    end
  end

  defp maybe_highlight(string, ast, var) do
    if is_fun_with_var?(ast, var) do
      IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()
    else
      string
    end
  end

  defp normalize_template_var(
         {{_, _, [{_, _, [:EEx, :Engine]}, _]}, _, [{:var!, _, [{:assigns, _, _}]}, key]},
         _
       ) do
    "@#{key}"
  end

  defp normalize_template_var(_, string), do: string

  def is_fun_with_var?(fun, var) do
    {_, acc} = Macro.prewalk(fun, [], &is_fun_var/2)
    if Enum.member?(acc, var), do: true, else: false
  end

  defp is_fun_var({:__aliases__, _, aliases} = ast, acc) do
    {ast, [Module.concat(aliases) | acc]}
  end

  defp is_fun_var({:render, _, [_, _, keylist]} = ast, acc) do
    {ast, Keyword.keys(keylist) ++ acc}
  end

  defp is_fun_var({:render, _, [_, keylist]} = ast, acc) when is_list(keylist) do
    {ast, Keyword.keys(keylist) ++ acc}
  end

  defp is_fun_var({:&, _, [idx]} = ast, acc), do: {ast, ["&#{idx}" | acc]}
  defp is_fun_var({var, _, _} = ast, acc), do: {ast, [var | acc]}
  defp is_fun_var(ast, acc), do: {ast, acc}
end
