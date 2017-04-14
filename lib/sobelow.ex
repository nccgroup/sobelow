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
  alias Sobelow.XSS
  alias Sobelow.SQL
  alias Sobelow.Traversal

  def run do
    app_name = Utils.get_app_name("mix.exs")
    web_root = if File.exists?("lib/#{String.downcase(app_name)}/web/router.ex") do
      "lib/#{String.downcase(app_name)}/"
    else
      "./"
    end

    base_app_module = if web_root === "" do
      Module.concat([app_name])
    else
      Module.concat(app_name, "Web")
    end

    # routes_path = web_root <> "router.ex"

    # This functionality isn't necessarily useful at the moment, but
    # it will be used for validation later on.
    # if File.exists?(routes_path) do
    #   Utils.get_routes(routes_path)
    # else
    #   IO.puts "Router.ex not found in default location.\n"
    # end

    root = if web_root === "./" do
      web_root <> "web/"
    else
      web_root
    end

#    root = "../hex/hexpm/lib/hexpm/"

    Config.fetch(web_root <> "web/")
    Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.each(fn file ->
        def_funs = Utils.get_def_funs(root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root <> "web/"))
    end)
  end

  def get_fun_vulns(fun, filename, web_root) do
    if String.ends_with?(filename, "_controller.ex") do
      XSS.get_vulns(fun, filename, web_root)
    end
    SQL.get_vulns(fun, filename)
    Traversal.get_vulns(fun, filename)
  end
end
