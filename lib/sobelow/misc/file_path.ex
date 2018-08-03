defmodule Sobelow.Misc.FilePath do
  @moduledoc ~S"""
  # Insecure use of `File` and `Path`

  In Elixir, `File` methods are null-terminated, while `Path`
  functions are not. This may cause security issues in certain
  situations. For example:

  ```
  user_input = "/var/www/secret.txt\0/name"

  path = Path.dirname(user_input)
  public_file = path <> "/public.txt"

  File.read(public_file)
  ```

  Because `Path` functions are not null-terminated, this
  will attempt to read the file, "/var/www/secret.txt\\0/public.txt".
  However, due to the null-byte termination of `File` functions
  "secret.txt" will ultimately be read.

  `File/Path` checks can be ignored with the following command:

      $ mix sobelow -i Misc.FilePath
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, meta_file) do
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each(vars, fn var ->
      add_finding(line_no, meta_file.filename, fun_name, fun, var, Utils.get_sev(params, var))
    end)
  end

  defp add_finding(line_no, filename, fun_name, fun, var, severity) do
    type = "Insecure use of `File` and `Path`"

    filename = filename |> String.replace("//", "/")
    context = Utils.get_context(filename, line_no)

    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          file: filename,
          function: "#{fun_name}",
          line: "#{line_no}",
          variable: var,
          context: context
        ]

        Sobelow.log_finding(finding, severity)

      "txt" ->
        Sobelow.log_finding(type, severity)

        IO.puts(Utils.finding_header(type, severity))
        IO.puts(Utils.finding_file_metadata(filename, fun_name, line_no))
        IO.puts(Utils.finding_variable(var))
        Utils.maybe_print_file_path_code(fun, var)
        IO.puts(Utils.finding_break())

      "compact" ->
        Utils.log_compact_finding(type, filename, line_no, severity)

      _ ->
        Sobelow.log_finding(type, severity)
    end
  end

  def parse_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    file_assigns = Utils.get_assigns_from(fun, [:File])
    path_assigns = Utils.get_assigns_from(fun, [:Path])

    path_vars =
      Utils.get_funs_by_module(fun, [:Path])
      |> Enum.map(&Utils.extract_opts(&1, 0))
      |> List.flatten()

    file_vars =
      Utils.get_funs_by_module(fun, [:File])
      |> Enum.map(&Utils.extract_opts(&1, 0))
      |> List.flatten()

    shared_path =
      Enum.filter(path_vars, fn var ->
        Enum.member?(file_assigns, var)
      end)

    shared_file =
      Enum.filter(file_vars, fn var ->
        Enum.member?(path_assigns, var)
      end)

    vars =
      Enum.filter(file_vars, fn var ->
        Enum.member?(path_vars, var)
      end)

    {vars ++ shared_file ++ shared_path, params, {fun_name, line_no}}
  end
end
