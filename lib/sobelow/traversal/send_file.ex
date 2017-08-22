defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)
    Enum.each vars, fn var ->
      add_finding(line_no, filename, fun_name,
                  fun, var, Utils.get_sev(params, var, severity))
    end
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  defp parse_def(fun) do
    {files, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 2, :send_file)
    {aliased_files,_,_} = Utils.get_fun_vars_and_meta(fun, 2, :send_file, [:Plug, :Conn])

    {files ++ aliased_files, params, {fun_name, line_no}}
  end

  def add_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "Directory Traversal in `send_file`", :send_file, [:Plug, :Conn])
  end

  def details() do
    Sobelow.Traversal.details()
  end
end
