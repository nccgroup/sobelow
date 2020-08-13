defmodule PhoenixWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :phoenix

  socket("/socket", PhoenixInternalsWeb.UserSocket,
    websocket: [check_origin: true],
    longpoll: false
  )
end
