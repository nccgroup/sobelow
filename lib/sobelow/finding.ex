defmodule Sobelow.Finding do
  @callback get_details() :: String.t

  defmacro __using__(_) do
    quote do
      @behaviour Sobelow.Finding
      def details() do
        if is_nil(@moduledoc) do
          get_details()
        else
          IO.ANSI.Docs.print(@moduledoc)
        end
      end

      def get_details() do
        Enum.each @submodules, fn sub ->
          apply(sub, :details, [])
        end
      end

      defoverridable [details: 0, get_details: 0]
    end
  end
end