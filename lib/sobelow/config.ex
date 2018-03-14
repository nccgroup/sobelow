defmodule Sobelow.Config do
  alias Sobelow.Utils
  alias Sobelow.Config.CSRF
  alias Sobelow.Config.CSP
  alias Sobelow.Config.Headers

  @submodules [
    Sobelow.Config.CSRF,
    Sobelow.Config.Headers,
    Sobelow.Config.CSP,
    Sobelow.Config.Secrets,
    Sobelow.Config.HTTPS,
    Sobelow.Config.HSTS
  ]

  use Sobelow.FindingType
  @skip_files ["dev.exs", "test.exs", "dev.secret.exs", "test.secret.exs"]

  def fetch(root, router) do
    allowed = @submodules -- Sobelow.get_ignored()
    ignored_files = Sobelow.get_env(:ignored_files)

    dir_path = root <> "config/"

    if File.dir?(dir_path) do
      configs =
        File.ls!(dir_path)
        |> Enum.filter(&want_to_scan?(dir_path <> &1, ignored_files))

      Enum.each(allowed, fn mod ->
        if mod in [CSRF, Headers, CSP] do
          Enum.each(router, fn path ->
            apply(mod, :run, [path, configs])
          end)
        else
          apply(mod, :run, [dir_path, configs])
        end
      end)
    end
  end

  defp want_to_scan?(conf, ignored_files) do
    if Path.extname(conf) === ".exs" && !Enum.member?(@skip_files, Path.basename(conf)) &&
         !Enum.member?(ignored_files, Path.expand(conf)),
       do: conf
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end
end
