defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding
  @finding_type "Traversal.SendFile: Directory Traversal in `send_file`"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low

    {findings, params, {fun_name, line_no}} = parse_def(fun)

    Enum.each(findings, fn {finding, var} ->
      Print.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Print.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  defp parse_def(fun) do
    {files, params, {fun_name, line_no}} = Parse.get_fun_vars_and_meta(fun, 2, :send_file)
    {aliased_files, _, _} = Parse.get_fun_vars_and_meta(fun, 2, :send_file, :Conn)

    {files ++ aliased_files, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.Traversal.details()
  end
end
