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
  * `--strict` - Exit when bad syntax is encountered
  * `--mark-skip-all` - Mark all printed findings as skippable
  * `--clear-skip` - Clear configuration added by `--mark-skip-all`
  * `--skip` - Skip functions flagged with `#sobelow_skip` or tagged with `--mark-skip-all`
  * `--router` - Specify router location
  * `--exit` - Return non-zero exit status
  * `--threshold` - Only return findings at or above a given confidence level
  * `--format` - Specify findings output format
  * `--quiet` - Return no output if there are no findings
  * `--compact` - Minimal, single-line findings
  * `--save-config` - Generates a configuration file based on command line options
  * `--config` - Run Sobelow with configuration file

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
  * XSS.HTML
  * SQL
  * SQL.Query
  * SQL.Stream
  * Config
  * Config.CSRF
  * Config.Headers
  * Config.CSP
  * Config.HTTPS
  * Config.HSTS
  * Config.Secrets
  * Config.CSWH
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
  * Traversal.SendDownload
  * Misc
  * Misc.BinToTerm
  * Misc.FilePath
  * RCE.EEx
  * RCE.CodeModule
  * CI
  * CI.System
  * CI.OS
  * DOS
  * DOS.StringToAtom
  * DOS.ListToAtom
  * DOS.BinToAtom

  """
  @switches [
    verbose: :boolean,
    root: :string,
    ignore: :string,
    ignore_files: :string,
    details: :string,
    all_details: :boolean,
    private: :boolean,
    strict: :boolean,
    diff: :string,
    skip: :boolean,
    mark_skip_all: :boolean,
    clear_skip: :boolean,
    router: :string,
    exit: :string,
    format: :string,
    config: :boolean,
    save_config: :boolean,
    quiet: :boolean,
    compact: :boolean,
    flycheck: :boolean,
    out: :string,
    threshold: :string
  ]

  @aliases [v: :verbose, r: :root, i: :ignore, d: :details, f: :format]

  # For escript entry
  def main(argv) do
    run(argv)
  end

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, aliases: @aliases, switches: @switches)

    root = Keyword.get(opts, :root, ".")
    config = Keyword.get(opts, :config, false)
    conf_file = Path.join(root, ".sobelow-conf")
    conf_file? = config && File.exists?(conf_file)

    opts =
      if is_nil(Keyword.get(opts, :exit)) && Enum.member?(argv, "--exit") do
        [{:exit, "low"} | opts]
      else
        opts
      end

    opts =
      if conf_file? do
        {:ok, opts} = File.read!(conf_file) |> Code.string_to_quoted()
        opts
      else
        opts
      end

    config = get_opts(opts, root, conf_file?)

    Application.put_all_env(sobelow: Map.to_list(config))

    if with_code = Keyword.get(opts, :with_code) do
      Mix.Shell.IO.info("WARNING: --with-code is deprecated, please use --verbose instead.\n")
      set_env(:verbose, with_code)
    end

    save_config = Keyword.get(opts, :save_config)

    cond do
      config.diff ->
        run_diff(argv)

      !is_nil(save_config) ->
        Sobelow.save_config(conf_file)

      !is_nil(config.all_details) ->
        Sobelow.all_details()

      !is_nil(config.details) ->
        Sobelow.details()

      true ->
        Sobelow.run(config)
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
    IO.puts(:os.cmd('diff sobelow.tempdiff ' ++ diff_target))
  end

  def set_env(key, value) do
    Application.put_env(:sobelow, key, value)
  end

  defp get_opts(opts, root, conf_file?) do
    verbose = Keyword.get(opts, :verbose, false)
    details = Keyword.get(opts, :details, nil)
    all_details = Keyword.get(opts, :all_details)
    private = Keyword.get(opts, :private, false)
    strict = Keyword.get(opts, :strict, false)
    diff = Keyword.get(opts, :diff, false)
    skip = Keyword.get(opts, :skip, false)
    mark_skip_all = Keyword.get(opts, :mark_skip_all, false)
    clear_skip = Keyword.get(opts, :clear_skip, false)
    router = Keyword.get(opts, :router)
    out = Keyword.get(opts, :out)

    exit_on =
      case String.downcase(Keyword.get(opts, :exit, "None")) do
        "high" -> :high
        "medium" -> :medium
        "low" -> :low
        _ -> false
      end

    format =
      cond do
        Keyword.get(opts, :quiet) -> "quiet"
        Keyword.get(opts, :compact) -> "compact"
        Keyword.get(opts, :flycheck) -> "flycheck"
        true -> Keyword.get(opts, :format, "txt") |> String.downcase()
      end

    format = out_format(out, format)

    {ignored, ignored_files} =
      if conf_file? do
        {Keyword.get(opts, :ignore, []),
         Keyword.get(opts, :ignore_files, []) |> Enum.map(&Path.expand(&1, root))}
      else
        ignored =
          Keyword.get(opts, :ignore, "")
          |> String.split(",")

        ignored_files =
          Keyword.get(opts, :ignore_files, "")
          |> String.split(",", trim: true)
          |> Enum.map(&Path.expand(&1, root))

        {ignored, ignored_files}
      end

    threshold =
      case String.downcase(Keyword.get(opts, :threshold, "low")) do
        "high" -> :high
        "medium" -> :medium
        _ -> :low
      end

    %Sobelow.Opts{
      root: root,
      verbose: verbose,
      diff: diff,
      details: details,
      private: private,
      strict: strict,
      skip: skip,
      mark_skip_all: mark_skip_all,
      clear_skip: clear_skip,
      router: router,
      exit_on: exit_on,
      format: format,
      ignored: ignored,
      ignored_files: ignored_files,
      all_details: all_details,
      out: out,
      threshold: threshold
    }
  end

  # Future updates will include format hinting based on the outfile name. Additional output
  # formats will also be added.
  defp out_format(nil, format), do: format
  defp out_format("", format), do: format

  defp out_format(_out, format) do
    cond do
      format in ["json", "quiet", "sarif"] -> format
      true -> "json"
    end
  end
end
