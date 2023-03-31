defmodule GoodRouter do
  @moduledoc false

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:protect_from_forgery)
  end
end
