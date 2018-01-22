defmodule SobelowTest.DOS.ListToAtomTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.DOS.ListToAtom

  test "Unsafe `List.to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, List.to_atom(test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def(ast) |> is_vuln?
  end

  test "Unsafe indirect `List.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, List.to_atom(params["test"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def(ast) |> is_vuln?
  end

  test "safe `String.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, List.to_atom("index")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute ListToAtom.parse_def(ast) |> is_vuln?
  end
end
