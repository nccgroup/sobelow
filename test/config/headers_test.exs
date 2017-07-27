defmodule SobelowTest.Config.HeadersTest do
  use ExUnit.Case
  alias Sobelow.Utils

  test "checks normal router for secure headers" do
  	router = "./test/fixtures/headers/good_router.ex"
    refute Utils.get_pipelines(router)
	|> Enum.any?(&Utils.is_vuln_pipeline(&1, :headers))
  end

  test "checks normal router for secure headers with additional headers" do
  	router = "./test/fixtures/headers/good_router_with_headers.ex"
    refute Utils.get_pipelines(router)
	|> Enum.any?(&Utils.is_vuln_pipeline(&1, :headers))
  end

  test "checks bad router without secure headers" do
  	router = "./test/fixtures/headers/bad_router.ex"
    assert Utils.get_pipelines(router)
	|> Enum.any?(&Utils.is_vuln_pipeline(&1, :headers))
  end
end