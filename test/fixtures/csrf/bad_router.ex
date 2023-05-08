# Router is missing plug :protect_from_forgery
defmodule BadRouter do
  @moduledoc false

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_flash)
  end
end
