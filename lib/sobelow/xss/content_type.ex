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
  @uid 28
  @finding_type "XSS.ContentType: XSS in `put_resp_content_type`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## put_resp_content_type(conn, content_type, charset \\ "utf-8")
  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 1, :put_resp_content_type, :Conn)
  end
end
