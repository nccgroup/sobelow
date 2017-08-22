defmodule Sobelow.Finding do
  defmacro __using__(_) do
    quote do
      def details() do
        IO.ANSI.Docs.print(@moduledoc)
      end

      defoverridable [details: 0]
    end
  end
end

defmodule Sobelow.FindingType do
  defmacro __using__(_) do
    quote do
      def details() do
        Enum.each @submodules, fn sub ->
          apply(sub, :details, [])
        end
      end

      defoverridable [details: 0]
    end
  end
end
