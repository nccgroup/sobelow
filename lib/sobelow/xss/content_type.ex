defmodule Sobelow.XSS.ContentType do
  @moduledoc """
  # XSS in `put_resp_content_type`

  If an attacker is able to set arbitrary content types for an
  HTTP response containing user input, the attacker is likely to
  be able to leverage this for cross-site scripting (XSS).

  For example, consider an endpoint that returns JSON with user
  input:

      {"json": "user_input"}

  If an attacker can control the content type set in the HTTP
  response, they can set it to "text/html" and update the
  JSON to the following in order to cause XSS:

      {"json": "<script>alert(document.domain)</script>"}

  Content Type checks can be ignored with the following command:

      $ mix sobelow -i XSS.ContentType
  """
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding
  @finding_type "XSS.ContentType: XSS in `put_resp_content_type`"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low
    {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

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

  ## put_resp_content_type(conn, content_type, charset \\ "utf-8")
  def parse_def(fun) do
    {vars, params, {fun_name, line_no}} =
      Parse.get_fun_vars_and_meta(fun, 1, :put_resp_content_type)

    {aliased_vars, _, _} = Parse.get_fun_vars_and_meta(fun, 1, :put_resp_content_type, :Conn)

    {vars ++ aliased_vars, params, {fun_name, line_no}}
  end
end
