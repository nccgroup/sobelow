defmodule Mix.Tasks.Sobelow do
  use Mix.Task
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.

  This tool should be run in the root of the project directory
  with the following command:

      mix sobelow

  ## Command line options

  * `--root -r` - Specify application root directory
  * `--verbose -v` - Print vulnerable code snippets
  * `--ignore -i` - Ignore modules
  * `--ignore-files` - Ignore files
  * `--details -d` - Get module details
  * `--all-details` - Get all module details
  * `--private` - Skip update checks
  * `--skip` - Skip functions flagged with `@sobelow_skip`
  * `--router` - Specify router location
  * `--exit` - Return non-zero exit status
  * `--format` - Specify findings output format
  * `--quiet` - Return no output if there are no findings
  * `--compact` - Minimal, single-line findings

  ## Ignoring modules

  If specific modules, or classes of modules are not relevant
  to the scan, it is possible to ignore them with a
  comma-separated list.

      mix sobelow -i XSS.Raw,Traversal

  ## Supported modules

  * XSS
  * XSS.Raw
  * XSS.SendResp
  * XSS.ContentType
  * SQL
  * SQL.Query
  * SQL.Stream
  * Config
  * Config.CSRF
  * Config.Headers
  * Config.HTTPS
  * Config.HSTS
  * Config.Secrets
  * Vuln
  * Vuln.CookieRCE
  * Vuln.HeaderInject
  * Vuln.PlugNull
  * Vuln.Redirect
  * Vuln.Coherence
  * Vuln.Ecto
  * Traversal
  * Traversal.SendFile
  * Traversal.FileModule
  * Misc
  * Misc.BinToTerm
  * Misc.FilePath
  * RCE.EEx
  * CI
  * CI.System
  * CI.OS
  * DOS
  * DOS.StringToAtom
  * DOS.ListToAtom
  * DOS.BinToAtom

  """
  @switches [verbose: :boolean,
             root: :string,
             ignore: :string,
             ignore_files: :string,
             details: :string,
             all_details: :boolean,
             private: :boolean,
             diff: :string,
             skip: :boolean,
             router: :string,
             exit: :string,
             format: :string,
             config: :boolean,
             save_config: :boolean,
             quiet: :boolean,
             compact: :boolean]

  @aliases  [v: :verbose, r: :root, i: :ignore, d: :details, f: :format]

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, aliases: @aliases, switches: @switches)

    root = Keyword.get(opts, :root, ".")
    config = Keyword.get(opts, :config, false)
    conf_file = root <> "/.sobelow-conf"
    conf_file? = config && File.exists?(conf_file)

    opts = if is_nil(Keyword.get(opts, :exit)) && Enum.member?(argv, "--exit") do
      [{:exit, "low"}|opts]
    else
      opts
    end
    opts = if conf_file? do
      {:ok, opts} = File.read!(conf_file) |> Code.string_to_quoted()
      opts
    else
      opts
    end

    {verbose, diff, details,
        private, skip, router,
        exit_on, format, ignored,
        ignored_files, all_details} = get_opts(opts, root, conf_file?)

    set_env(:verbose, verbose)
    if with_code = Keyword.get(opts, :with_code) do
      Mix.Shell.IO.info("WARNING: --with-code is deprecated, please use --verbose instead.\n")
      set_env(:verbose, with_code)
    end
    set_env(:root, root)
    set_env(:details, details)
    set_env(:private, private)
    set_env(:skip, skip)
    set_env(:router, router)
    set_env(:exit_on, exit_on)
    set_env(:format, format)
    set_env(:ignored, ignored)
    set_env(:ignored_files, ignored_files)

    save_config = Keyword.get(opts, :save_config)

    cond do
      diff ->
        run_diff(argv)
      !is_nil(save_config) ->
        Sobelow.save_config(conf_file)
      !is_nil(all_details) ->
        Sobelow.all_details()
      !is_nil(details) ->
        Sobelow.details()
      true ->
        Sobelow.run()
    end
  end

  # This diff check is strictly used for testing/debugging and
  # isn't meant for general use.
  def run_diff(argv) do
    diff_idx = Enum.find_index(argv, fn i -> i === "--diff" end)
    {_, list} = List.pop_at(argv, diff_idx)
    {diff_target, list} = List.pop_at(list, diff_idx)
    args = Enum.join(list, " ") |> to_charlist()
    diff_target = to_charlist(diff_target)
    :os.cmd('mix sobelow ' ++ args ++ ' > sobelow.tempdiff')
    IO.puts :os.cmd('diff sobelow.tempdiff ' ++ diff_target)
  end

  def set_env(key, value) do
    Application.put_env(:sobelow, key, value)
  end

  defp get_opts(opts, root, conf_file?) do
    verbose = Keyword.get(opts, :verbose, false)
    details = Keyword.get(opts, :details, nil)
    all_details = Keyword.get(opts, :all_details)
    private = Keyword.get(opts, :private, false)
    diff = Keyword.get(opts, :diff, false)
    skip = Keyword.get(opts, :skip, false)
    router = Keyword.get(opts, :router)
    exit_on = case String.downcase(Keyword.get(opts, :exit, "None")) do
      "high" -> :high
      "medium" -> :medium
      "low" -> :low
      _ -> false
    end
    format = cond do
      Keyword.get(opts, :quiet) -> "quiet"
      Keyword.get(opts, :compact) -> "compact"
      true -> Keyword.get(opts, :format, "txt") |> String.downcase()
    end

    {ignored, ignored_files} =
      if conf_file? do
        {Keyword.get(opts, :ignore, []), Keyword.get(opts, :ignore_files, []) |> Enum.map(&Path.expand(&1, root))}
      else
        ignored =
          Keyword.get(opts, :ignore, "")
          |> String.split(",")

        ignored_files =
          Keyword.get(opts, :ignore_files, "")
          |> String.split(",")
          |> Enum.reject(fn file -> file == "" end)
          |> Enum.map(&Path.expand(&1, root))

        {ignored, ignored_files}
      end

    {verbose, diff, details, private, skip, router, exit_on, format, ignored, ignored_files, all_details}
  end
end
