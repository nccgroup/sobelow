defmodule SobelowTest.DOS.StringToAtomTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.DOS.StringToAtom

  test "Unsafe `String.to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, String.to_atom(test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "Unsafe indirect `String.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, String.to_atom(params["test"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "safe `String.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, String.to_atom("index")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute StringToAtom.parse_def(ast) |> is_vuln?
  end
end