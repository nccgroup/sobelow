defmodule SobelowTest.Config.HeadersTest do
  use ExUnit.Case
  alias Sobelow.Config

  test "checks normal router for secure headers" do
    router = "./test/fixtures/headers/good_router.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end

  test "checks normal router for secure headers with additional headers" do
    router = "./test/fixtures/headers/good_router_with_headers.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end

  test "checks bad router without secure headers" do
    router = "./test/fixtures/headers/bad_router.ex"

    assert Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end
end
