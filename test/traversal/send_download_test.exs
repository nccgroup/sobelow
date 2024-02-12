defmodule SobelowTest.Traversal.SendDownload do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.Traversal.SendDownload

  test "vulnerable send_download" do
    func = """
    def index(conn, %{"test" => test}) do
      send_download conn, {:file, test}
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendDownload.parse_def(ast) |> vuln?
  end

  test "safe send_download" do
    func = """
    def index(conn, %{"test" => test}) do
      send_download conn, {:binary, test}
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendDownload.parse_def(ast) |> vuln?
  end

  test "safe send_download with filename key" do
    func = """
    def index(conn, %{"test" => test}) do
      send_download conn, {:binary, test}, filename: "test"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendDownload.parse_def(ast) |> vuln?

    func = """
    def index(conn, %{"test" => test}) do
      conn
      |> send_download({:binary, test}, filename: "test")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute SendDownload.parse_def(ast) |> vuln?
  end

  test "vulnerable Phoenix.Controller.send_download" do
    func = """
    def index(conn, %{"test" => test}) do
      Phoenix.Controller.send_download(conn, {:file, test})
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert SendDownload.parse_def(ast) |> vuln?
  end
end
