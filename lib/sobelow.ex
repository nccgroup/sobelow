defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config[:version]

  alias Sobelow.Utils
  alias Sobelow.Config
  alias Sobelow.XSS
  alias Sobelow.SQL
  alias Sobelow.Traversal
  alias Sobelow.Misc
  alias Mix.Shell.IO

  def run() do
    IO.info print_banner()
    project_root = get_env(:root) <> "/"
    app_name = Utils.get_app_name(project_root <> "mix.exs")
    web_root = get_root(app_name, project_root)

    root = if String.ends_with?(web_root, "./"), do: web_root <> "web/", else: web_root

    if !File.exists?(web_root <> "web/router.ex") do
      IO.error("This does not appear to be a Phoenix application.")
      System.halt(0)
    end

    Config.fetch(web_root)
    Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.each(fn file ->
        def_funs = Utils.get_def_funs(root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root <> "web/"))
    end)
  end

  def get_env(key) do
    Application.get_env(:sobelow, key)
  end

  defp print_banner() do
    """
    ##############################################
    #                                            #
    #          Running Sobelow - v#{@v}          #
    #  Created by Griffin Byatt - @griffinbyatt  #
    #     NCC Group - https://nccgroup.trust     #
    #                                            #
    ##############################################
    """
  end

  defp get_root(app_name, project_root) do
    if File.exists?(project_root <> "lib/#{String.downcase(app_name)}/web/router.ex") do
      project_root <> "lib/#{String.downcase(app_name)}/"
    else
      project_root <> "./"
    end
  end

  defp get_fun_vulns(fun, filename, web_root) do
    if String.ends_with?(filename, "_controller.ex") do
      XSS.get_vulns(fun, filename, web_root)
    end
    SQL.get_vulns(fun, filename)
    Traversal.get_vulns(fun, filename)
    Misc.get_vulns(fun, filename)
  end
end
