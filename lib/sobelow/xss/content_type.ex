defmodule Sobelow.XSS.ContentType do
  @moduledoc """
  # XSS in `put_resp_content_type`


  Content Type checks can be ignored with the following command:

      $ mix sobelow -i XSS.ContentType
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_finding(line_no, filename, fun_name, fun, var, severity || :high)
      else
        print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
      end
    end
  end

  ## put_resp_content_type(conn, content_type, charset \\ "utf-8")
  defp parse_def(fun) do
    {vars, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 1, :put_resp_content_type)
    {aliased_vars,_,_} = Utils.get_fun_vars_and_meta(fun, 1, :put_resp_content_type, [:Plug, :Conn])

    {vars ++ aliased_vars, params, {fun_name, line_no}}
  end


  def print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "XSS in `put_resp_content_type`", :put_resp_content_type, [:Plug, :Conn])
  end
end