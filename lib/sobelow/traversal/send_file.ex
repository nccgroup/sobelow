defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    # If the file is a controller, check for `send_file` as well as
    # `Plug.Conn.send_file`. If it is not a controller, look for
    # `Plug.Conn.send_file` only.
    if String.ends_with?(filename, "_controller.ex") do
      {vars, params, {fun_name, [{_, line_no}]}} = parse_send_file_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    else
      {vars, params, {fun_name, [{_, line_no}]}} = parse_aliased_send_file_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    end
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  ##
  ## send_file has optional params, so the parameter we care about
  ## for traversal won't be at a definite location. This is a
  ## simple solution to the problem.
  defp parse_send_file_def(fun) do
    {files, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 2, :send_file)
    {aliased_files,_,_} = Utils.get_fun_vars_and_meta(fun, 2, :send_file, [:Plug, :Conn])

    {files ++ aliased_files, params, {fun_name, line_no}}
  end

  defp parse_aliased_send_file_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 2, :send_file, [:Plug, :Conn])
  end

  def print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "Directory Traversal in `send_file`", :send_file, [:Plug, :Conn])
  end

  def get_details() do
    Sobelow.Traversal.details()
  end
end
