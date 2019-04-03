defmodule SobelowTest.UtilsTest do
  use ExUnit.Case

  test "Utils.get_app_name/1 understands module attributes" do
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix.exs") == "foo_bar"
  end
end
