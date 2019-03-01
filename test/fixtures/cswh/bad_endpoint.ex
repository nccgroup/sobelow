defmodule PhoenixWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :phoenix

  socket("/socket", PhoenixInternalsWeb.UserSocket,
    websocket: [check_origin: false],
    longpoll: false
  )
end
