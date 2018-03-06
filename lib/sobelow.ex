defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config()[:version]
  @submodules [
    Sobelow.XSS,
    Sobelow.SQL,
    Sobelow.Traversal,
    Sobelow.RCE,
    Sobelow.Misc,
    Sobelow.Config,
    Sobelow.CI,
    Sobelow.DOS,
    Sobelow.Vuln
  ]

  alias Sobelow.Utils
  alias Sobelow.Config
  alias Sobelow.Vuln
  alias Sobelow.FindingLog
  alias Sobelow.MetaLog
  alias Mix.Shell.IO, as: MixIO
  # Remove directory structure check for release candidate
  # prior to 1.0
  def run() do
    project_root = get_env(:root) <> "/"
    if !get_env(:private), do: version_check(project_root)

    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if !is_binary(app_name), do: file_error()

    {web_root, lib_root} = get_root(app_name, project_root)

    root =
      if String.ends_with?(web_root, "./") do
        web_root <> "web/"
      else
        lib_root
      end

    router = get_router(app_name, web_root)
    if !File.exists?(router), do: no_router()

    ignored = get_ignored()
    allowed = @submodules -- ignored

    # Pulling out function definitions before kicking
    # off the test pipeline to avoid dumping warning
    # messages into the findings output.
    root_meta_files = get_meta_files(root)
    template_meta_files = get_meta_templates(root)

    # If web_root ends with the app_name, then it is the
    # more recent version of Phoenix. Meaning, all files are
    # in the lib directory, so we don't need to re-scan
    # lib_root separately.
    phx_post_1_2? =
      String.ends_with?(web_root, "/#{app_name}/") ||
        String.ends_with?(web_root, "/#{app_name}_web/")

    libroot_meta_files = if !phx_post_1_2?, do: get_meta_files(lib_root), else: []

    FindingLog.start_link()
    MetaLog.start_link()

    MetaLog.add_templates(template_meta_files)

    # This is where the core testing-pipeline starts.
    #
    # - Print banner
    # - Check configuration
    # - Remove config check from "allowed" modules
    # - Scan funcs from the root
    # - Scan funcs from the libroot
    if not (format() in ["quiet", "compact", "json"]), do: IO.puts(:stderr, print_banner())
    Application.put_env(:sobelow, :app_name, app_name)

    if Enum.member?(allowed, Config), do: Config.fetch(project_root, router)
    if Enum.member?(allowed, Vuln), do: Vuln.get_vulns(project_root)

    allowed = allowed -- [Config, Vuln]

    Enum.each(root_meta_files, fn meta_file ->
      meta_file.def_funs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, meta_file, root, allowed))
    end)

    Enum.each(libroot_meta_files, fn meta_file ->
      meta_file.def_funs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, meta_file, "", allowed))
    end)

    # Future template handling will look something like this.
    # XSS checks should be fully handled earlier, and excluded from
    # the second template pass.
    # template_meta_files = MetaLog.get_templates()
    # Enum.each template_meta_files, fn {_, meta_file} ->
    #   Sobelow.XSS.get_raw_template_vulns(meta_file)
    # end
    #
    # Enum.each(template_meta_files, fn {_, meta_file} ->
    #   get_fun_vulns(meta_file.ast, meta_file, root, allowed)
    # end)

    if format() != "txt" do
      print_output()
    else
      IO.puts(:stderr, "... SCAN COMPLETE ...\n")
    end

    exit_with_status()
  end

  defp print_output() do
    details =
      case format() do
        "json" ->
          FindingLog.json(@v)

        "quiet" ->
          FindingLog.quiet()

        _ ->
          nil
      end

    if !is_nil(details), do: IO.puts(details)
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

        _ ->
          0
      end

    exit_status = if is_nil(status), do: 0, else: status
    System.halt(exit_status)
  end

  def details() do
    mod =
      get_env(:details)
      |> get_mod

    if is_nil(mod) do
      MixIO.error("A valid module was not selected.")
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

  def save_config(conf_file) do
    conf = """
    [
      verbose: #{get_env(:verbose)},
      private: #{get_env(:private)},
      skip: #{get_env(:skip)},
      router: "#{get_env(:router)}",
      exit: "#{get_env(:exit_on)}",
      format: "#{get_env(:format)}",
      ignore: ["#{Enum.join(get_env(:ignored), "\", \"")}"],
      ignore_files: ["#{Enum.join(get_env(:ignored_files), "\", \"")}"]
    ]
    """

    yes? =
      if File.exists?(conf_file) do
        MixIO.yes?("The file .sobelow-conf already exists. Are you sure you want to overwrite?")
      else
        true
      end

    if yes? do
      File.write!(conf_file, conf)
      MixIO.info("Updated .sobelow-conf")
    end
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

    cond do
      File.dir?(project_root <> "lib/#{app_name}_web") ->
        # New phoenix RC structure
        {lib_root <> "#{app_name}_web/", lib_root}

      File.dir?(project_root <> "lib/#{app_name}/web/") ->
        # RC 1 phx dir structure
        {lib_root <> "#{app_name}/", lib_root}

      true ->
        # Original dir structure
        {project_root <> "./", lib_root}
    end
  end

  defp get_router(app_name, web_root) do
    router_path =
      if Path.basename(web_root) == "#{app_name}_web" do
        "router.ex"
      else
        "web/router.ex"
      end

    case get_env(:router) do
      nil -> web_root <> router_path
      "" -> web_root <> router_path
      router -> router
    end
  end

  defp get_meta_templates(root) do
    ignored_files = get_env(:ignored_files)

    Utils.template_files(root)
    |> Enum.reject(&is_ignored_file(&1, ignored_files))
    |> Enum.map(&get_template_meta/1)
    |> Map.new()
  end

  defp get_template_meta(filename) do
    meta_funs = Utils.get_meta_template_funs(filename)
    raw = meta_funs.raw
    ast = meta_funs.ast
    filename = Utils.normalize_path(filename)

    {
      filename,
      %{
        filename: filename,
        raw: raw,
        ast: [ast],
        is_controller?: false
      }
    }
  end

  defp get_meta_files(root) do
    ignored_files = get_env(:ignored_files)

    Utils.all_files(root)
    |> Enum.reject(&is_ignored_file(&1, ignored_files))
    |> Enum.map(&get_file_meta/1)
  end

  defp get_file_meta(filename) do
    ast = Utils.ast(filename)
    meta_funs = Utils.get_meta_funs(ast)
    def_funs = meta_funs.def_funs
    use_funs = meta_funs.use_funs

    %{
      filename: Utils.normalize_path(filename),
      def_funs: def_funs,
      is_controller?: Utils.is_controller?(use_funs)
    }
  end

  defp get_fun_vulns({fun, skips}, meta_file, web_root, mods) do
    skip_mods =
      skips
      |> Enum.map(&get_mod/1)

    Enum.each(mods -- skip_mods, fn mod ->
      params = [fun, meta_file, web_root, skip_mods]
      apply(mod, :get_vulns, params)
    end)
  end

  defp get_fun_vulns(fun, meta_file, web_root, mods) do
    get_fun_vulns({fun, []}, meta_file, web_root, mods)
  end

  defp combine_skips([]), do: []

  defp combine_skips([head | tail] = funs) do
    if get_env(:skip), do: combine_skips(head, tail), else: funs
  end

  defp combine_skips(prev, []), do: [prev]
  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | []]), do: [{prev, skips}]

  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | tail]) do
    [h | t] = tail
    [{prev, skips} | combine_skips(h, t)]
  end

  defp combine_skips(prev, rest) do
    [h | t] = rest
    [prev | combine_skips(h, t)]
  end

  defp no_router() do
    message = """
    WARNING: Sobelow cannot find the router. If this is a Phoenix application
    please use the `--router` flag to specify the router's location.
    """

    IO.puts(:stderr, message)
    ignored = get_env(:ignored)

    Application.put_env(
      :sobelow,
      :ignored,
      ignored ++ ["Config.CSRF", "Config.Headers", "Config.CSP"]
    )
  end

  defp file_error() do
    MixIO.error("This does not appear to be a Phoenix application.")
    System.halt(0)
  end

  defp version_check(project_root) do
    cfile = project_root <> ".sobelow"
    time = DateTime.utc_now() |> DateTime.to_unix()

    if File.exists?(cfile) do
      {timestamp, _} =
        case File.read!(cfile) do
          "sobelow-" <> timestamp -> Integer.parse(timestamp)
          _ -> file_error()
        end

      if time - 12 * 60 * 60 > timestamp do
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

    # update to sobelow.io for future versions
    url = 'https://griffinbyatt.com/static/sobelow-version'

    IO.puts(:stderr, "Checking Sobelow version...\n")

    case :httpc.request(:get, {url, []}, [{:timeout, 10000}], []) do
      {:ok, {{_, 200, _}, _, vsn}} ->
        Version.parse!(String.trim(to_string(vsn)))

      _ ->
        MixIO.error("Error fetching version number.\n")
        @v
    end
  after
    :inets.stop(:httpc, :sobelow)
  end

  defp maybe_prompt_update(time, cfile) do
    installed_vsn = Version.parse!(@v)

    cmp =
      get_sobelow_version()
      |> Version.compare(installed_vsn)

    case cmp do
      :gt ->
        MixIO.error("""
        A new version of Sobelow is available:
        mix archive.install hex sobelow
        """)

      _ ->
        nil
    end

    timestamp = "sobelow-" <> to_string(time)
    File.write(cfile, timestamp)
  end

  def get_mod(mod_string) do
    case mod_string do
      "XSS" -> Sobelow.XSS
      "XSS.Raw" -> Sobelow.XSS.Raw
      "XSS.SendResp" -> Sobelow.XSS.SendResp
      "XSS.ContentType" -> Sobelow.XSS.ContentType
      "XSS.HTML" -> Sobelow.XSS.HTML
      "SQL" -> Sobelow.SQL
      "SQL.Query" -> Sobelow.SQL.Query
      "SQL.Stream" -> Sobelow.SQL.Stream
      "Misc" -> Sobelow.Misc
      "Misc.BinToTerm" -> Sobelow.Misc.BinToTerm
      "Misc.FilePath" -> Sobelow.Misc.FilePath
      "RCE" -> Sobelow.RCE
      "RCE.EEx" -> Sobelow.RCE.EEx
      "RCE.CodeModule" -> Sobelow.RCE.CodeModule
      "Config" -> Sobelow.Config
      "Config.CSRF" -> Sobelow.Config.CSRF
      "Config.Headers" -> Sobelow.Config.Headers
      "Config.CSP" -> Sobelow.Config.CSP
      "Config.Secrets" -> Sobelow.Config.Secrets
      "Config.HTTPS" -> Sobelow.Config.HTTPS
      "Config.HSTS" -> Sobelow.Config.HSTS
      "Vuln" -> Sobelow.Vuln
      "Vuln.CookieRCE" -> Sobelow.Vuln.CookieRCE
      "Vuln.HeaderInject" -> Sobelow.Vuln.HeaderInject
      "Vuln.PlugNull" -> Sobelow.Vuln.PlugNull
      "Vuln.Redirect" -> Sobelow.Vuln.Redirect
      "Vuln.Coherence" -> Sobelow.Vuln.Coherence
      "Vuln.Ecto" -> Sobelow.Vuln.Ecto
      "Traversal" -> Sobelow.Traversal
      "Traversal.SendFile" -> Sobelow.Traversal.SendFile
      "Traversal.FileModule" -> Sobelow.Traversal.FileModule
      "Traversal.SendDownload" -> Sobelow.Traversal.SendDownload
      "CI" -> Sobelow.CI
      "CI.System" -> Sobelow.CI.System
      "CI.OS" -> Sobelow.CI.OS
      "DOS" -> Sobelow.DOS
      "DOS.StringToAtom" -> Sobelow.DOS.StringToAtom
      "DOS.ListToAtom" -> Sobelow.DOS.ListToAtom
      "DOS.BinToAtom" -> Sobelow.DOS.BinToAtom
      _ -> nil
    end
  end

  def get_ignored() do
    get_env(:ignored)
    |> Enum.map(&get_mod/1)
  end

  def is_vuln?({vars, _, _}) do
    cond do
      length(vars) == 0 ->
        false

      true ->
        true
    end
  end

  defp is_ignored_file(filename, ignored_files) do
    Enum.any?(ignored_files, fn ignored_file ->
      String.ends_with?(ignored_file, filename)
    end)
  end
end
