defmodule Sobelow.Config do
  alias Sobelow.Utils
  alias Sobelow.Config.{CSRF, Secrets, HTTPS}

  def fetch(root, web_root) do
    CSRF.run(web_root)
    Secrets.run(root)
    HTTPS.run(root)
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      Utils.get_configs(secret, file)
    else
      []
    end
  end
end