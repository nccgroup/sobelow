defmodule Sobelow do
  @moduledoc """
  Documentation for Sobelow.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Sobelow.hello
      :world

  """
  alias Sobelow.Utils
  alias Sobelow.Config

  def run do
    app_name = Utils.get_app_name("mix.exs")
    web_root = if File.exists?("lib/#{String.downcase(app_name)}/web/router.ex") do
      "lib/#{String.downcase(app_name)}/web/"
    else
      "web/"
    end

    base_app_module = if web_root === "web/" do
      Module.concat([app_name])
    else
      Module.concat(app_name, "Web")
    end

    routes_path = web_root <> "router.ex"

    if File.exists?(routes_path) do
      Utils.get_routes(routes_path)
      IO.puts("\n")
    else
      IO.puts "Router.ex not found in default location.\n"
    end

    Config.hardcoded_secrets()
  end
end
