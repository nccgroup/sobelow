defmodule Sobelow.Vuln.Ecto do
  @moduledoc """
  # Ecto Version Lacks Protection Mechanism

  For more information visit:
  https://github.com/advisories/GHSA-2xxx-fhc8-9qvq

  Ecto checks can be ignored with the following command:

      $ mix sobelow -i Vuln.Ecto
  """
  alias Sobelow.Config
  alias Sobelow.Vuln

  @uid 24
  @finding_type "Vuln.Ecto: Known Vulnerable Dependency - Update Ecto"

  use Sobelow.Finding

  @vuln_vsn ["2.2.0"]

  def run(root) do
    plug_conf = root <> "/deps/ecto/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Config.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(
              plug_conf,
              vsn,
              "Ecto",
              "Missing `is_nil` requirement",
              "CVE-2017-20166",
              "Ecto"
            )
          end

        _ ->
          nil
      end
    end
  end
end
