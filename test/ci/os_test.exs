defmodule SobelowTest.CI.OSTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.CI.OS

  test "Command Injection in `:os.cmd`" do
    func = """
    def index(conn, %{"test" => test}) do
      :os.cmd(test, [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert OS.parse_def(ast) |> is_vuln?
  end

  test "Command Injection in indirect `:os.cmd`" do
    func = """
    def index(conn, params) do
      :os.cmd(params["test"], [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert OS.parse_def(ast) |> is_vuln?
  end

  test "safe `:os.cmd`" do
    func = """
    def index(conn, %{"test" => test}) do
      :os.cmd("ls", [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute OS.parse_def(ast) |> is_vuln?
  end
end
