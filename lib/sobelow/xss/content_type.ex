defmodule Sobelow.XSS.ContentType do
  @moduledoc """
  # XSS via `put_resp_content_type`


  Content Type checks can be ignored with the following command:

      $ mix sobelow -i XSS.ContentType
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    if String.ends_with?(filename, "_controller.ex") do
      {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    else
      {vars, params, {fun_name, [{_, line_no}]}} = parse_aliased_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    end
  end

  ## put_resp_content_type(conn, content_type, charset \\ "utf-8")
  defp parse_def(fun) do
    {files, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 1, :put_resp_content_type)
    {aliased_files,_,_} = Utils.get_fun_vars_and_meta(fun, 1, :put_resp_content_type, [:Plug, :Conn])

    {files ++ aliased_files, params, {fun_name, line_no}}
  end

  defp parse_aliased_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 1, :put_resp_content_type, [:Plug, :Conn])
  end

  def print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "XSS via `put_resp_content_type`", :put_resp_content_type, [:Plug, :Conn])
  end
end