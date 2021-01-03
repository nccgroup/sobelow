defmodule Sobelow.IO do
  @moduledoc """
  IO helpers. Mostly mirror Mix.Shell.IO, but Mix will not always be available
  to Sobelow.
  """
  def error(message) do
    IO.puts(:stderr, IO.ANSI.format([:red, :bright, message]))
  end

  def yes?(message) do
    answer = IO.gets(message <> " [Yn] ")
    is_binary(answer) and String.trim(answer) in ["", "y", "Y", "yes", "YES", "Yes"]
  end

  def info(message) do
    IO.puts(IO.ANSI.format(message))
  end
end
