defmodule SobelowTest.XSS.SendRespTest do
  use ExUnit.Case
  alias Sobelow.XSS.SendResp

  test "vulnerable send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendResp.parse_def(ast) |> is_vuln?
  end

  test "vulnerable aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendResp.parse_def(ast) |> is_vuln?
  end

  test "vulnerable alternative aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendResp.parse_def(ast) |> is_vuln?
  end

  test "safe send_resp due to content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/plain")
       |> send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendResp.parse_def(ast) |> is_vuln?
  end

  test "safe send_resp" do
    func = """
    def index(conn, _params) do
      put_resp_content_type(conn, "text/html")
      |> send_resp(200, "body")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendResp.parse_def(ast) |> is_vuln?
  end

  def is_vuln?({vars, is_html, _, _}) do
    cond do
      length(vars) > 0 && is_html ->
        true

      true ->
        false
    end
  end
end
