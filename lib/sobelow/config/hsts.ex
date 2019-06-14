defmodule Sobelow.Config.HSTS do
  @moduledoc """
  # HSTS

  The HTTP Strict Transport Security (HSTS) header helps
  defend against man-in-the-middle attacks by preventing
  unencrypted connections.

  HSTS checks can be ignored with the following command:

      $ mix sobelow -i Config.HSTS
  """
  alias Sobelow.Config
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Config.HSTS: HSTS Not Enabled"

  def run(dir_path, configs) do
    Enum.each(configs, fn conf ->
      path = dir_path <> conf

      Config.get_configs_by_file(:https, path)
      |> handle_https(path)
    end)
  end

  defp handle_https(opts, file) do
    # If HTTPS configs were found in any config file and there
    # are no accompanying HSTS configs, add an HSTS finding.
    if length(opts) > 0 && length(Utils.get_configs(:force_ssl, file)) === 0 do
      add_finding(file)
    end
  end

  defp add_finding(file) do
    filename = Utils.normalize_path(file)
    reason = "HSTS configuration details could not be found in `#{Path.basename(file)}`."

    case Sobelow.format() do
      "json" ->
        finding = [
          type: @finding_type,
          file: filename,
          line: 0
        ]

        Sobelow.log_finding(finding, :medium)

      "txt" ->
        Sobelow.log_finding(@finding_type, :medium)

        Utils.print_custom_finding_metadata(nil, reason, :medium, @finding_type, [])

      "compact" ->
        Utils.log_compact_finding(@finding_type, :medium)

      _ ->
        Sobelow.log_finding(@finding_type, :medium)
    end
  end
end
