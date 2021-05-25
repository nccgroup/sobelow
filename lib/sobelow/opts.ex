defmodule Sobelow.Opts do
  defstruct [
    :root,
    :verbose,
    :diff,
    :details,
    :private,
    :strict,
    :skip,
    :mark_skip_all,
    :clear_skip,
    :router,
    :exit_on,
    :format,
    :ignored,
    :ignored_files,
    :all_details,
    :out,
    :threshold
  ]
end
