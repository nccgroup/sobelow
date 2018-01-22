defmodule SobelowTest.XSS.ContentTypeTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.XSS.ContentType

  test "vulnerable put_resp_content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, test)
       |> send_file(200, "file.txt")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ContentType.parse_def(ast) |> is_vuln?
  end

  test "vulnerable aliased put_resp_content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, test)
       |> send_file(200, "file.txt")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ContentType.parse_def(ast) |> is_vuln?
  end

  test "vulnerable indirect aliased put_resp_content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, ImageMime.get(test))
       |> send_file(200, "file.txt")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ContentType.parse_def(ast) |> is_vuln?
  end

  test "safe put_resp_content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/plain")
       |> send_file(200, "file.txt")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute ContentType.parse_def(ast) |> is_vuln?
  end
end
