defmodule Sobelow.Config do
  alias Sobelow.Utils
  alias Sobelow.Config.CSRF
  @submodules [Sobelow.Config.CSRF,
               Sobelow.Config.Secrets,
               Sobelow.Config.HTTPS,
               Sobelow.Config.HSTS]

  use Sobelow.Finding
  @skip_files ["dev.exs", "test.exs", "dev.secret.exs", "test.secret.exs"]

  def fetch(root, router) do
    allowed = @submodules -- Sobelow.get_ignored()

    dir_path = root <> "config/"

    if File.dir?(dir_path) do
      configs =
        File.ls!(dir_path)
        |> Enum.filter(&want_to_scan?/1)

      Enum.each allowed, fn mod ->
        path = if mod === CSRF, do: router, else: dir_path
        apply(mod, :run, [path, configs])
      end
    end
  end

  defp want_to_scan?(conf) do
    if Path.extname(conf) === ".exs" && !Enum.member?(@skip_files, conf), do: conf
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end
end
