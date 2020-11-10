defmodule SobelowTest.Config.ConfigTest do
  use ExUnit.Case
  alias Sobelow.Config

  test "Extracts config" do
    config = "./test/fixtures/utils/config.exs"
    assert Config.get_configs(:security_option, config) != []
  end

  test "Handles nil config" do
    config = "./test/fixtures/utils/nil_config.exs"
    assert Config.get_configs(:security_option, config) == []
  end
end
