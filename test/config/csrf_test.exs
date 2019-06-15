defmodule SobelowTest.Config.CSRFTest do
  use ExUnit.Case
  alias Sobelow.Config

  test "checks normal router" do
    router = "./test/fixtures/csrf/good_router.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.is_vuln_pipeline?(&1, :csrf))
  end

  test "checks normal router with named session key" do
    router = "./test/fixtures/csrf/good_router_with_session_key.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.is_vuln_pipeline?(&1, :csrf))
  end

  test "checks normal router with with" do
    router = "./test/fixtures/csrf/good_router_with_with.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.is_vuln_pipeline?(&1, :csrf))
  end

  test "checks bad router" do
    router = "./test/fixtures/csrf/bad_router.ex"

    assert Config.get_pipelines(router)
           |> Enum.any?(&Config.is_vuln_pipeline?(&1, :csrf))
  end
end
