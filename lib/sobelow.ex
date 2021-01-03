defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config()[:version]
  @home "~/.sobelow"
  @vsncheck "sobelow-vsn-check"
  @skips ".sobelow-skips"
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
  alias Sobelow.Parse
  alias Sobelow.Vuln
  alias Sobelow.Finding
  alias Sobelow.FindingLog
  alias Sobelow.MetaLog
  alias Sobelow.Fingerprint
  alias Sobelow.IO, as: MixIO

  def run() do
    project_root = get_env(:root) <> "/"
    version_check()

    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if !is_binary(app_name), do: file_error()

    # If web_root ends with the app_name, then it is the
    # more recent version of Phoenix. Meaning, all files are
    # in the lib directory, so we don't need to re-scan
    # lib_root separately.
    phx_post_1_2? = !File.dir?(project_root <> "web")

    lib_root =
      if phx_post_1_2? do
        project_root <> "lib"
      else
        project_root <> "web"
      end

    ignored = get_ignored()
    allowed = @submodules -- ignored

    # Pulling out function definitions before kicking
    # off the test pipeline to avoid dumping warning
    # messages into the findings output.
    root_meta_files = get_meta_files(lib_root)
    template_meta_files = get_meta_templates(lib_root)

    {libroot_meta_files, tmp_default_router} =
      if !phx_post_1_2? do
        libroot_meta_files = get_meta_files(project_root <> "lib")
        default_router = project_root <> "/web/router.ex"

        {libroot_meta_files, default_router}
      else
        {[], ""}
      end

    default_router = get_router(tmp_default_router, phx_post_1_2?)

    {routers, endpoints} =
      get_phoenix_files(root_meta_files ++ libroot_meta_files, default_router)

    if Enum.empty?(routers), do: no_router()

    init_state(project_root, template_meta_files)

    if get_env(:clear_skip), do: clear_skip(project_root)

    # This is where the core testing-pipeline starts.
    #
    # - Print banner
    # - Check configuration
    # - Remove config check from "allowed" modules
    # - Scan funcs from the root
    # - Scan funcs from the libroot
    if not (format() in ["quiet", "compact", "flycheck", "json"]),
      do: IO.puts(:stderr, print_banner())

    Application.put_env(:sobelow, :app_name, app_name)

    if Enum.member?(allowed, Config), do: Config.fetch(project_root, routers, endpoints)
    if Enum.member?(allowed, Vuln), do: Vuln.get_vulns(project_root)

    allowed = allowed -- [Config, Vuln]

    Enum.each(root_meta_files, fn meta_file ->
      meta_file.def_funs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, meta_file, project_root, allowed))
    end)

    Enum.each(libroot_meta_files, fn meta_file ->
      meta_file.def_funs
      |> combine_skips()
      |> Enum.each(&get_fun_vulns(&1, meta_file, "", allowed))
    end)

    Enum.each(template_meta_files, fn {_, meta_file} ->
      if Sobelow.XSS in allowed, do: Sobelow.XSS.get_template_vulns(meta_file)
    end)

    # Enum.each(template_meta_files, fn {_, meta_file} ->
    #   get_fun_vulns(meta_file.ast, meta_file, root, allowed)
    # end)

    if format() != "txt" do
      print_output()
    else
      IO.puts(:stderr, "... SCAN COMPLETE ...\n")
    end

    if get_env(:mark_skip_all), do: mark_skip_all(project_root)

    exit_with_status()
  end

  defp init_state(project_root, template_meta_files) do
    FindingLog.start_link()
    MetaLog.start_link()
    Fingerprint.start_link()
    load_ignored_fingerprints(project_root)
    MetaLog.add_templates(template_meta_files)
  end

  defp print_output() do
    details =
      case output_format() do
        "json" ->
          FindingLog.json(@v)

        "quiet" ->
          FindingLog.quiet()

        "sarif" ->
          FindingLog.sarif(@v)

        _ ->
          nil
      end

    if !is_nil(details) do
      print_std_or_file(details)
    end
  end

  defp print_std_or_file(details) do
    case get_env(:out) do
      nil -> IO.puts(details)
      "" -> IO.puts(details)
      out -> File.write(out, details)
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

        _ ->
          0
      end

    if exit_on && !is_nil(status) do
      System.halt(status)
    end
  end

  def details() do
    mod =
      get_env(:details)
      |> get_mod

    if is_nil(mod) do
      MixIO.error("A valid module was not selected.")
    else
      apply(mod, :details, []) |> IO.puts()
    end
  end

  def log_finding(%Finding{} = finding) do
    log_finding(finding.type, finding)
  end

  def log_finding(details, %Finding{} = finding) do
    if loggable?(finding.fingerprint, finding.confidence) do
      Fingerprint.put(finding.fingerprint)
      FindingLog.add({details, finding}, finding.confidence)
    end
  end

  def loggable?(fingerprint, severity) do
    !(get_env(:skip) && Fingerprint.member?(fingerprint)) &&
      meets_threshold?(severity)
  end

  def all_details() do
    @submodules
    |> Enum.map(&apply(&1, :details, []))
    |> List.flatten()
    |> Enum.each(&IO.puts(&1))
  end

  def rules() do
    @submodules
    |> Enum.flat_map(&apply(&1, :rules, []))
  end

  def finding_modules() do
    @submodules
    |> Enum.flat_map(&apply(&1, :finding_modules, []))
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
      out: "#{get_env(:out)}",
      threshold: "#{get_env(:threshold)}",
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

  def meets_threshold?(severity) do
    threshold =
      case get_env(:threshold) do
        :high -> [:high]
        :medium -> [:high, :medium]
        _ -> [:high, :medium, :low]
      end

    severity in threshold
  end

  def format() do
    case get_env(:format) do
      "sarif" -> "json"
      "flycheck" -> "compact"
      format -> format
    end
  end

  def output_format() do
    get_env(:format)
  end

  def get_env(key) do
    Application.get_env(:sobelow, key)
  end

  defp print_banner() do
    """
    ##############################################
    #                                            #
    #          Running Sobelow - v#{@v}         #
    #  Created by Griffin Byatt - @griffinbyatt  #
    #     NCC Group - https://nccgroup.trust     #
    #                                            #
    ##############################################
    """
  end

  defp get_router("", true) do
    case get_env(:router) do
      nil -> ""
      "" -> ""
      router -> Path.expand(router)
    end
  end

  defp get_router(tmp_default_router, _) do
    case get_env(:router) do
      nil -> tmp_default_router
      "" -> tmp_default_router
      router -> router
    end
    |> Path.expand()
  end

  defp get_phoenix_files(meta_files, router) do
    phoenix_files =
      Enum.reduce(meta_files, %{routers: [], endpoints: []}, fn meta_file, acc ->
        cond do
          meta_file.is_router? ->
            Map.update!(acc, :routers, &[meta_file.file_path | &1])

          meta_file.is_endpoint? ->
            Map.update!(acc, :endpoints, &[meta_file.file_path | &1])

          true ->
            acc
        end
      end)

    uniq_phoenix_files =
      if File.exists?(router) do
        Map.update!(phoenix_files, :routers, fn routers ->
          Enum.uniq(routers ++ [router])
        end)
      else
        phoenix_files
      end

    {uniq_phoenix_files.routers, uniq_phoenix_files.endpoints}
  end

  defp get_meta_templates(root) do
    ignored_files = get_env(:ignored_files)

    Utils.template_files(root)
    |> Enum.reject(&is_ignored_file(&1, ignored_files))
    |> Enum.map(&get_template_meta/1)
    |> Map.new()
  end

  defp get_template_meta(filename) do
    meta_funs = Parse.get_meta_template_funs(filename)
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
    ast = Parse.ast(filename)
    meta_funs = Parse.get_meta_funs(ast)
    def_funs = meta_funs.def_funs
    use_funs = meta_funs.use_funs

    %{
      filename: Utils.normalize_path(filename),
      file_path: Path.expand(filename),
      def_funs: def_funs,
      is_controller?: Utils.is_controller?(use_funs),
      is_router?: Utils.is_router?(use_funs),
      is_endpoint?: Utils.is_endpoint?(use_funs)
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
      ignored ++ ["Config.CSRF", "Config.CSRFRoute", "Config.Headers", "Config.CSP"]
    )
  end

  defp file_error() do
    message = """
    This does not appear to be a Phoenix application. If this is an Umbrella application,
    each application should be scanned separately.
    """

    MixIO.error(message)
    System.halt(0)
  end

  defp clear_skip(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      File.rm!(cfile)
    end

    System.halt(0)
  end

  defp mark_skip_all(project_root) do
    cfile = project_root <> @skips

    case Fingerprint.new_skips() do
      [] ->
        nil

      fingerprints ->
        {:ok, iofile} = :file.open(cfile, [:append])
        fingerprints = Enum.join(fingerprints, "\n")
        :file.write(iofile, ["\n", fingerprints])
        :file.close(iofile)
    end
  end

  defp load_ignored_fingerprints(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      {:ok, iofile} = :file.open(cfile, [:read])

      :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
      :file.close(iofile)
    end
  end

  defp load_ignored_fingerprints({:ok, fingerprint}, iofile) do
    to_string(fingerprint) |> String.trim() |> Fingerprint.put_ignore()
    :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
  end

  defp load_ignored_fingerprints(:eof, _), do: nil
  defp load_ignored_fingerprints(_, _), do: nil

  defp version_check() do
    config =
      System.get_env("SOBELOW_HOME") ||
        @home
        |> Path.expand()
        |> Path.join(@vsncheck)

    home = Path.dirname(config)

    if File.exists?(home) do
      version_check(config)
    else
      File.mkdir_p!(home)
      version_check(config)
    end
  end

  defp version_check(config) do
    time = DateTime.utc_now() |> DateTime.to_unix()

    if File.exists?(config) do
      {:ok, iofile} = :file.open(config, [:read])

      {timestamp, _} =
        case :file.read_line(iofile) do
          {:ok, 'sobelow-' ++ timestamp} -> to_string(timestamp) |> Integer.parse()
          _ -> file_error()
        end

      :file.close(iofile)

      if time - 12 * 60 * 60 > timestamp do
        maybe_prompt_update(time, config)
      end
    else
      maybe_prompt_update(time, config)
    end
  end

  defp get_sobelow_version() do
    # Modeled after old Mix.Utils.read_path
    {:ok, _} = Application.ensure_all_started(:ssl)
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = :inets.start(:httpc, [{:profile, :sobelow}])

    url = 'https://sobelow.io/version'

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

    unless get_env(:private) do
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
    end

    timestamp = "sobelow-" <> to_string(time)

    case :file.open(cfile, [:write, :read]) do
      {:ok, iofile} ->
        :ok = :file.pwrite(iofile, 0, timestamp)
        :ok = :file.close(iofile)

      _ ->
        File.write(cfile, timestamp)
    end
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
      "Config.CSRFRoute" -> Sobelow.Config.CSRFRoute
      "Config.Headers" -> Sobelow.Config.Headers
      "Config.CSP" -> Sobelow.Config.CSP
      "Config.Secrets" -> Sobelow.Config.Secrets
      "Config.HTTPS" -> Sobelow.Config.HTTPS
      "Config.HSTS" -> Sobelow.Config.HSTS
      "Config.CSWH" -> Sobelow.Config.CSWH
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
