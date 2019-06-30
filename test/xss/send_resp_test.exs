defmodule SobelowTest.XSS.SendRespTest do
  use ExUnit.Case
  alias Sobelow.XSS.SendResp
  alias Sobelow.Finding

  test "default content_type send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       send_resp(conn, 200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  test "vulnerable send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  test "vulnerable aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  test "vulnerable alternative aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  test "safe send_resp due to content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/plain")
       |> send_resp(200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  test "safe send_resp" do
    func = """
    def index(conn, _params) do
      put_resp_content_type(conn, "text/html")
      |> send_resp(200, "body")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Stream.map(&SendResp.set_confidence/1)
    |> Stream.reject(&SendResp.nil_confidence?/1)
    |> Enum.each(&assert(is_vuln?(&1)))
  end

  def is_vuln?(%Finding{confidence: nil}), do: false
  def is_vuln?(%Finding{}), do: true
end
