defmodule SobelowTest.CI.SystemTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.CI.System

  test "Command Injection in `System.cmd`" do
    func = """
    def index(conn, %{"test" => test}) do
      System.cmd(test, [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert System.parse_def(ast) |> is_vuln?
  end

  test "Command Injection in indirect `System.cmd`" do
    func = """
    def index(conn, %{"test" => test}) do
      System.cmd(get_cmd(test), [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert System.parse_def(ast) |> is_vuln?
  end

  test "safe `System.cmd`" do
    func = """
    def index(conn, %{"test" => test}) do
      System.cmd("ls", [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute System.parse_def(ast) |> is_vuln?
  end
end