defmodule Sobelow.Finding do
  defmacro __using__(_) do
    quote do
      alias Sobelow.FindingLog

      def details() do
        if is_nil(@moduledoc) do
          get_details()
        else
          IO.ANSI.Docs.print(@moduledoc)
        end
      end

      def log_finding(finding, severity) do
        FindingLog.add(finding, severity)
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
