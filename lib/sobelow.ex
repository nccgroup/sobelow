defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config[:version]
  @submodules [Sobelow.XSS,
               Sobelow.SQL,
               Sobelow.Traversal,
               Sobelow.Misc,
               Sobelow.Config]

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
    if is_nil(app_name), do: file_error()
    web_root = get_root(app_name, project_root)

    root = if String.ends_with?(web_root, "./"), do: web_root <> "web/", else: web_root

    if !File.exists?(web_root <> "web/router.ex"), do: file_error()

    ignored = get_ignored()
    allowed = @submodules -- ignored

    if Enum.member?(allowed, Config), do: Config.fetch(project_root, web_root)

    Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.each(fn file ->
        def_funs = Utils.get_def_funs(root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root <> "web/", allowed -- [Config]))
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

  defp get_fun_vulns(fun, filename, web_root, mods) do
    Enum.each mods, fn mod ->
      apply(mod, :get_vulns, [fun, filename, web_root])
    end
  end

  defp file_error() do
    IO.error("This does not appear to be a Phoenix application.")
    System.halt(0)
  end

  def get_mod(mod_string) do
    case mod_string do
      "XSS" -> Sobelow.XSS
      "XSS.Raw" -> Sobelow.XSS.Raw
      "XSS.SendResp" -> Sobelow.XSS.SendResp
      "SQL" -> Sobelow.SQL
      "SQL.Inject" -> Sobelow.SQL.Inject
      "Misc" -> Sobelow.Misc
      "Misc.BinToTerm" -> Sobelow.Misc.BinToTerm
      "Config" -> Sobelow.Config
      "Config.CSRF" -> Sobelow.Config.CSRF
      "Config.Secrets" -> Sobelow.Config.Secrets
      "Config.HTTPS" -> Sobelow.Config.HTTPS
      "Traversal" -> Sobelow.Traversal
      "Traversal.SendFile" -> Sobelow.Traversal.SendFile
      "Traversal.FileModule" -> Sobelow.Traversal.FileModule
      _ -> nil
    end
  end

  def get_ignored() do
    get_env(:ignored)
    |> Enum.map(&get_mod/1)
  end
end
