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
               Sobelow.Config,
               Sobelow.CI,
               Sobelow.DOS,
               Sobelow.Vuln]

  alias Sobelow.Utils
  alias Sobelow.Config
  alias Sobelow.Vuln
  alias Sobelow.FindingLog
  alias Mix.Shell.IO
  # In order to support the old application structure, as well as the
  # upcoming application structure (ie all in lib directory, vs pulled
  # into a web directory), there are a number of different "roots" in
  # use.
  def run() do
    project_root = get_env(:root) <> "/"
    if !get_env(:private), do: version_check(project_root)

    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if !is_binary(app_name), do: file_error()
    {web_root, lib_root} = get_root(app_name, project_root)

    root = if String.ends_with?(web_root, "./"), do: web_root <> "web/", else: lib_root

    router = 
      case get_env(:router) do
        nil -> web_root <> "web/router.ex"
        router -> router
      end

    if !File.exists?(router), do: no_router()

    ignored = get_ignored()
    allowed = @submodules -- ignored

    # Pulling out function definitions before kicking
    # off the test pipeline to avoid dumping warning
    # messages into the findings output.
    root_defs = Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(fn file ->
      {file, Utils.get_def_funs(root <> file)}
    end)

    # If web_root ends with the app_name, then it is the
    # more recent version of Phoenix. Meaning, all files are
    # in the lib directory, so we don't need to re-scan
    # lib_root separately.
    libroot_defs =
      case !String.ends_with?(web_root, "/#{app_name}/") do
        true ->
          Utils.all_files(lib_root)
          |> Enum.reject(&is_nil/1)
          |> Enum.map(fn file ->
            filename = lib_root <> file
            {filename, Utils.get_def_funs(filename)}
          end)
        _ -> []
      end

    FindingLog.start_link()

    # This is where the core testing-pipeline starts.
    #
    # - Print banner
    # - Check configuration
    # - Remove config check from "allowed" modules
    # - Scan funcs from the root
    # - Scan funcs from the libroot
    Elixir.IO.puts :stderr, print_banner()
    Application.put_env(:sobelow, :app_name, app_name)

    if Enum.member?(allowed, Config), do: Config.fetch(project_root, router)
    if Enum.member?(allowed, Vuln), do: Vuln.get_vulns(project_root)

    allowed = allowed -- [Config, Vuln]

    Enum.each(root_defs, fn {filename, defs} ->
      defs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, filename, root, allowed))
    end)

    Enum.each(libroot_defs, fn {filename, defs} ->
      defs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, filename, "", allowed))
    end)

    if format() != "txt" do
      print_output()
    else
      Elixir.IO.puts :stderr, "... SCAN COMPLETE ...\n"
    end

    exit_with_status()
  end

  defp print_output() do
    case format() do
      "json" -> Elixir.IO.puts FindingLog.json(@v)
      _ -> nil
    end
  end

  defp exit_with_status() do
    exit_on = get_env(:exit_on)
    finding_logs = FindingLog.log()

    high_count = length(finding_logs[:high])
    medium_count = length(finding_logs[:medium])
    low_count = length(finding_logs[:low])

    status =
      case exit_on do
        :high ->
          if high_count > 0, do: 1
        :medium ->
          if high_count + medium_count > 0, do: 1
        :low ->
          if high_count + medium_count + low_count > 0, do: 1
        _ -> 0
      end

    System.halt(status)
  end

  def details() do
    mod = get_env(:details)
    |> get_mod

    if is_nil(mod) do
      IO.error "A valid module was not selected."
    else
      apply(mod, :details, [])
    end
  end

  def log_finding(finding, severity) do
    FindingLog.add(finding, severity)
  end

  def all_details() do
    @submodules
    |> Enum.each(&apply(&1, :details, []))
  end

  def format() do
    get_env(:format)
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
    lib_root = project_root <> "lib/"
    if File.dir?(project_root <> "lib/#{app_name}/web/") do
      {lib_root <> "#{app_name}/", lib_root}
    else
      {project_root <> "./", lib_root}
    end
  end

  defp get_fun_vulns({fun, skips}, filename, web_root, mods) do
    skip_mods = skips
    |> Enum.map(&get_mod/1)

    Enum.each mods -- skip_mods, fn mod ->
      apply(mod, :get_vulns, [fun, filename, web_root, skip_mods])
    end
  end
  defp get_fun_vulns(fun, filename, web_root, mods) do
    Enum.each mods, fn mod ->
      apply(mod, :get_vulns, [fun, filename, web_root])
    end
  end

  defp combine_skips([]), do: []
  defp combine_skips([head|tail] = funs) do
    if get_env(:skip), do: combine_skips(head, tail), else: funs
  end
  defp combine_skips(prev, []), do: [prev]
  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | []]), do: [{prev, skips}]
  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | tail]) do
    [h|t] = tail
    [{prev, skips}|combine_skips(h, t)]
  end
  defp combine_skips(prev, rest) do
    [h|t] = rest
    [prev|combine_skips(h, t)]
  end

  defp no_router() do
    message = """
    ERROR: Sobelow cannot find the router. Ensure that this is a Phoenix 
    application, or use the `--router` flag to specify the router's 
    location.
    """
    IO.error(message)
    ignored = get_env(:ignored)
    Application.put_env(:sobelow, :ignored, ignored ++ ["Config.CSRF"])
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
    # Modeled after old Mix.Utils.read_path
    {:ok, _} = Application.ensure_all_started(:ssl)
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = :inets.start(:httpc, [{:profile, :sobelow}])

    case :httpc.request('https://griffinbyatt.com/static/sobelow-version') do
      {:ok, {{_, 200, _}, _, vsn}} ->
        Version.parse! String.trim(to_string(vsn))
      _ ->
        IO.error("Error fetching version number.\n")
        @v
    end
  after
    :inets.stop(:httpc, :sobelow)
  end

  defp maybe_prompt_update(time, cfile) do
    installed_vsn = Version.parse! @v

    cmp = get_sobelow_version()
    |> Version.compare(installed_vsn)

    case cmp do
      :gt ->
        IO.error """
        A new version of Sobelow is available:
        mix archive.install hex sobelow
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
      "SQL.Query" -> Sobelow.SQL.Query
      "SQL.Stream" -> Sobelow.SQL.Stream
      "Misc" -> Sobelow.Misc
      "Misc.BinToTerm" -> Sobelow.Misc.BinToTerm
      "Misc.FilePath" -> Sobelow.Misc.FilePath
      "Config" -> Sobelow.Config
      "Config.CSRF" -> Sobelow.Config.CSRF
      "Config.Secrets" -> Sobelow.Config.Secrets
      "Config.HTTPS" -> Sobelow.Config.HTTPS
      "Vuln" -> Sobelow.Vuln
      "Vuln.CookieRCE" -> Sobelow.CookeRCE
      "Vuln.HeaderInject" -> Sobelow.Vuln.HeaderInject
      "Vuln.PlugNull" -> Sobelow.Vuln.PlugNull
      "Vuln.Redirect" -> Sobelow.Vuln.Redirect
      "Traversal" -> Sobelow.Traversal
      "Traversal.SendFile" -> Sobelow.Traversal.SendFile
      "Traversal.FileModule" -> Sobelow.Traversal.FileModule
      "CI" -> Sobelow.CI
      "CI.System" -> Sobelow.CI.System
      "CI.OS" -> Sobelow.CI.OS
      "DOS" -> Sobelow.DOS
      "DOS.StringToAtom" -> Sobelow.DOS.StringToAtom
      "DOS.ListToAtom" -> Sobelow.DOS.ListToAtom
      _ -> nil
    end
  end

  def get_ignored() do
    get_env(:ignored)
    |> Enum.map(&get_mod/1)
  end
end
