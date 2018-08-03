defmodule Sobelow.Vuln.Coherence do
  alias Sobelow.Utils
  alias Sobelow.Vuln
  use Sobelow.Finding

  @vuln_vsn ["<=0.5.1"]

  def run(root) do
    plug_conf = root <> "/deps/coherence/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Utils.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(
              vsn,
              "Coherence",
              "Permissive parameters and privilege escalation",
              "TBA - https://github.com/smpallen99/coherence/issues/270",
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
