defmodule Sobelow.Formatter do
  @moduledoc false
  @type finding :: %Sobelow.Finding{}
  @type log :: %{high: [finding], medium: [finding], low: [finding]}

  @callback format_findings(log :: log, String.t) :: term

end
