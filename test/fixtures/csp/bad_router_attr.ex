defmodule BadRouter do
  @moduledoc false

  @csp %{"Not-Content-Security-Policy" => "default-src 'self'"}

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers, @csp)
  end
end
