defmodule SobelowTest.XSS.RawTemplateTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.XSS.Raw

  test "vulnerable raw in template" do
    temp = """
    <%= raw(@user_input) %>
    """

    ast = EEx.compile_string(temp)

    assert Raw.parse_raw_def(ast) |> is_vuln?
  end

  test "vulnerable piped raw in template" do
    temp = """
    <%= @user_input |> raw() %>
    """

    ast = EEx.compile_string(temp)

    assert Raw.parse_raw_def(ast) |> is_vuln?
  end

  test "safe raw in template" do
    temp = """
    <%= raw("<h1>Test</h1>") %>
    """

    ast = EEx.compile_string(temp)

    refute Raw.parse_raw_def(ast) |> is_vuln?
  end
end
