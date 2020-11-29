defmodule Sobelow.Vuln.Ecto do
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
              "TBA - https://groups.google.com/forum/#!topic/elixir-ecto/0m4NPfg_MMU",
              "Ecto"
            )
          end

        _ ->
          nil
      end
    end
  end

  def details() do
    Sobelow.Vuln.details()
  end
end
