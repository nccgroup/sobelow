defmodule SobelowTest.SarifTest do
  use ExUnit.Case

  test "Unique rule ids" do
    ids = Sobelow.rules() |> Enum.map(&(&1.id))

    assert Enum.uniq(ids) |> length() == length(ids)
  end

  test "All finding modules have an id" do
    ids = Sobelow.finding_modules |> Enum.map(&apply(&1, :id, []))

    assert Enum.uniq(ids) |> length() == length(ids)
  end
end
