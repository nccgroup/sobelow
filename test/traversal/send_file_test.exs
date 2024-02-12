defmodule SobelowTest.Traversal.SendFile do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.Traversal.SendFile

  test "vulnerable send_file" do
    func = """
    def index(conn, %{"test" => test}) do
      send_file(conn, 200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendFile.parse_def(ast) |> vuln?
  end

  test "vulnerable aliased send_file" do
    func = """
    def index(conn, %{"test" => test}) do
      Plug.Conn.send_file(conn, 200, test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendFile.parse_def(ast) |> vuln?
  end

  test "vulnerable indirect aliased send_file" do
    func = """
    def index(conn, %{"test" => test}) do
      Plug.Conn.send_file(conn, 200, Path.expand(test))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendFile.parse_def(ast) |> vuln?
  end

  test "safe send_file" do
    func = """
    def index(conn, %{"test" => _test}) do
      send_file(conn, 200, "file.txt")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendFile.parse_def(ast) |> vuln?
  end
end
