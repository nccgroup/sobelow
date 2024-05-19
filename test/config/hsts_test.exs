defmodule SobelowTest.Config.HstsTest do
  use ExUnit.Case
  alias Sobelow.Config.HSTS

  setup do
    Application.put_env(:sobelow, :format, "json")
    Sobelow.Fingerprint.start_link()
    Sobelow.FindingLog.start_link()

    :ok
  end

  test "complains when force_ssl is missing in prod.exs" do
    HSTS.run("./test/fixtures/hsts/", ["missing_prod.exs"])
    assert Sobelow.FindingLog.json("1") =~ "Config.HSTS: HSTS Not Enabled"
  end

  test "does not complain when force_ssl is present in prod.exs" do
    HSTS.run("./test/fixtures/hsts/", ["present_prod.exs"])
    refute Sobelow.FindingLog.json("1") =~ "Config.HSTS: HSTS Not Enabled"
  end

  test "does not complain when force_ssl is missing in runtime.exs" do
    HSTS.run("./test/fixtures/hsts/", ["runtime.exs"])
    refute Sobelow.FindingLog.json("1") =~ "Config.HSTS: HSTS Not Enabled"
  end
end
