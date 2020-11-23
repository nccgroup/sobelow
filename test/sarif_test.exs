defmodule SobelowTest.SarifTest do
  use ExUnit.Case

  test "Unique rule ids" do
    ids = Sobelow.rules() |> Enum.map(&(&1.id))

    assert Enum.uniq(ids) |> length() == length(ids)
  end
end
