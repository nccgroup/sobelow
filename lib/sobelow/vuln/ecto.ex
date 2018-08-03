defmodule Sobelow.Vuln.Ecto do
  alias Sobelow.Utils
  alias Sobelow.Vuln
  use Sobelow.Finding

  @vuln_vsn ["2.2.0"]

  def run(root) do
    plug_conf = root <> "/deps/ecto/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Utils.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(
              vsn,
              "Ecto",
              "Missing `is_nil` requirement",
              "TBA - https://groups.google.com/forum/#!topic/elixir-ecto/0m4NPfg_MMU",
              plug_conf
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
