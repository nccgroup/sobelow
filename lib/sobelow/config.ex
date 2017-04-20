defmodule Sobelow.Config do
  alias Sobelow.Utils
  alias Sobelow.Config.{CSRF, Secrets, HTTPS}
  @submodules [Sobelow.Config.CSRF,
               Sobelow.Config.Secrets,
               Sobelow.Config.HTTPS]

  def fetch(root, web_root) do
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      path = if mod === CSRF, do: web_root, else: root
      apply(mod, :run, [path])
    end
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end
end