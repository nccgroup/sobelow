defmodule SobelowTest.Config.HttpsTest do
  use ExUnit.Case
  alias Sobelow.Config.HTTPS

  setup do
    Application.put_env(:sobelow, :format, "json")
    Sobelow.Fingerprint.start_link()
    Sobelow.FindingLog.start_link()

    :ok
  end

  test "does not log when force_ssl is present in prod.exs" do
    refute HTTPS.run("./test/fixtures/https/", ["prod.exs"])
  end

  test "does not log when force_ssl is present in runtime.exs" do
    refute HTTPS.run("./test/fixtures/https/", ["runtime.exs"])
  end

  test "does not log when files don't exist" do
    refute HTTPS.run("./test/fixtures/https/", ["prod.exs"], ["prod_does_not_exist.exs"])
  end

  test "does not log when one of the files has the https enabled" do
    refute HTTPS.run("./test/fixtures/https/", ["prod.exs"], [
             "prod_without_https.exs",
             "prod.exs"
           ])
  end

  test "logs when config files exist but https in not found any of them" do
    HTTPS.run("./test/fixtures/https/", ["prod_without_https.exs"], ["prod_without_https.exs"])
    assert Sobelow.FindingLog.json("1") =~ "Config.HTTPS: HTTPS Not Enabled"
  end
end
