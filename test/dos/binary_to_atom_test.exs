defmodule SobelowTest.DOS.BinaryToAtomTest do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.DOS.BinToAtom

  test "Unsafe atom interpolation" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, :"foo\#{test}"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToAtom.parse_def(ast) |> vuln?
  end

  test "Unsafe indirect atom interpolation" do
    func = """
    def index(conn, params) do
      render conn, :"foo\#{params["test"]}"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToAtom.parse_def(ast) |> vuln?
  end

  test "safe atom interpolation" do
    func = """
    def index(conn, params) do
      render conn, :"foo\#{1}"
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute BinToAtom.parse_def(ast) |> vuln?
  end
end
