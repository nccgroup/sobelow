defmodule SobelowTest.XSS.HTMLTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.XSS.HTML

  test "vulnerable html" do
    func = """
    def index(conn, %{"test" => test}) do
      html conn, test
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert HTML.parse_def(ast) |> is_vuln?
  end

  test "vulnerable interpolated html" do
    func = """
    def index(conn, %{"input" => input}) do
      html conn, "<h1>\#{input}</h1>"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert HTML.parse_def(ast) |> is_vuln?
  end

  test "safe html" do
    func = """
    def index(conn, _params) do
      html conn, "<h1>Safe!</h1>"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute HTML.parse_def(ast) |> is_vuln?
  end
end