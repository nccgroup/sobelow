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
  alias Mix.Shell.IO
  # In order to support the old application structure, as well as the
  # upcoming application structure (ie all in lib directory, vs pulled
  # into a web directory), there are a number of different "roots" in
  # use.
  def run() do
    IO.info print_banner()

    project_root = get_env(:root) <> "/"
    version_check(project_root)

    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if is_nil(app_name), do: file_error()
    {web_root, lib_root} = get_root(app_name, project_root)

    root = if String.ends_with?(web_root, "./"), do: web_root <> "web/", else: web_root

    if !File.exists?(web_root <> "web/router.ex"), do: file_error()

    ignored = get_ignored()
    allowed = @submodules -- ignored

    if Enum.member?(allowed, Config), do: Config.fetch(project_root, web_root)

    Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.each(fn file ->
        Utils.get_def_funs(root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root <> "web/", allowed -- [Config]))
    end)

    if web_root !== lib_root do
      Utils.all_files(lib_root)
      |> Enum.reject(&is_nil/1)
      |> Enum.each(fn file ->
        Utils.get_def_funs(lib_root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root, allowed -- [Config]))
      end)
    end

    IO.info "... SCAN COMPLETE ..."
  end

  def details() do
    get_env(:details)
    |> get_mod
    |> apply(:details, [])
  end

  def all_details() do
    @submodules
    |> Enum.each(&apply(&1, :details, []))
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
    lib_root = project_root <> "lib/#{String.downcase(app_name)}/"
    if File.exists?(project_root <> "lib/#{String.downcase(app_name)}/web/router.ex") do
      {lib_root, lib_root}
    else
      {project_root <> "./", lib_root}
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

  defp version_check(project_root) do
    cfile = project_root <> ".sobelow"
    time = DateTime.utc_now() |> DateTime.to_unix()

    if File.exists?(cfile) do
      {timestamp, _} = case File.read!(cfile) do
        "sobelow-" <> timestamp -> Integer.parse(timestamp)
        _ -> file_error()
      end
      if time - 12*60*60 > timestamp do
        maybe_prompt_update(time, cfile)
      end
    else
      maybe_prompt_update(time, cfile)
    end
  end

  defp get_sobelow_version() do
    {:ok, vsn} = Mix.Utils.read_path("https://griffinbyatt.com/static/sobelow-version")
    Version.parse! vsn
  end

  defp maybe_prompt_update(time, cfile) do
    installed_vsn = Version.parse! @v

    cmp = get_sobelow_version()
    |> Version.compare(installed_vsn)

    case cmp do
      :gt ->
        IO.error """
        A new version of Sobelow is available:
        {{ARCHIVE INSTALL COMMAND}}
        """
      _ -> nil
    end

    timestamp = "sobelow-" <> to_string(time)
    File.write(cfile, timestamp)
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
