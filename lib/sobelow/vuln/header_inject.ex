defmodule Sobelow.Vuln.HeaderInject do
  @moduledoc """
  # Plug Version Vulnerable to Header Injection

  For more information visit:
  https://github.com/advisories/GHSA-9h73-w7ch-rh73

  Header Injection checks can be ignored with the following command:

      $ mix sobelow -i Vuln.HeaderInject
  """
  alias Sobelow.Config
  alias Sobelow.Vuln

  @uid 25
  @finding_type "Vuln.HeaderInject: Known Vulnerable Dependency - Update Plug"

  use Sobelow.Finding

  # we could _probably_ remove some of these versions since if Sobelow is running,
  # it means there is a minimum version of Elixir on the system which the lower
  # versions of Plug wouldn't support - will leave for now to reflect CVE
  @vuln_vsn ["<=1.3.4 and >=1.3.0", "<=1.2.4 and >=1.2.0", "<=1.1.8 and >=1.1.0", "<=1.0.5"]

  def run(root) do
    plug_conf = root <> "/deps/plug/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Config.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(
              plug_conf,
              vsn,
              "Plug",
              "Header Injection",
              "CVE-2018-1000883",
              "HeaderInject"
            )
          end

        _ ->
          nil
      end
    end
  end

  def details do
    Sobelow.Vuln.details()
  end
end
