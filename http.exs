Mix.install([
  :hpax,
  :x509,
  :bandit,
  :mint
])

ExUnit.start(autorun: false)

defmodule HTTPTest do
  use ExUnit.Case

  setup_all do
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=localhost", validity: 1)

    ssl_options = [
      cert: X509.Certificate.to_der(cert),
      key: {:RSAPrivateKey, X509.PrivateKey.to_der(key)}
    ]

    {:ok, ssl_options: ssl_options}
  end

  defp hello(conn, _) do
    conn
    |> Plug.Conn.put_resp_content_type("text/plain")
    |> Plug.Conn.send_resp(200, "hello from bandit\n")
  end

  test "http1 - client" do
    port = 8000

    start_supervised!({Bandit, plug: &hello/2, scheme: :http, port: port, startup_log: false})

    {:ok, sock} =
      :gen_tcp.connect(~c"localhost", port,
        inet_backend: :socket,
        mode: :binary,
        active: true,
        packet: {&HTTP1.decode/2, :response}
      )

    :ok = :gen_tcp.send(sock, "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")

    assert_receive {:http, ^sock,
                    [
                      {:status, ref, 200},
                      {:headers, ref, _},
                      {:data, ref, "hello from bandit\n"},
                      {:done, ref}
                    ]}
  end

  test "http1 - server" do
    port = 8000

    {:ok, sock} =
      :gen_tcp.listen(port,
        inet_backend: :socket,
        mode: :binary,
        active: true,
        packet: {&HTTP1.decode/2, :request},
        reuseaddr: true
      )

    Task.start_link(fn ->
      {:ok, sock} = :gen_tcp.accept(sock)

      assert_receive {:http, ^sock,
                      [
                        {:request, ref, :GET, "/hello"},
                        {:headers, ref, _headers},
                        {:data, ref, "foo"},
                        {:done, ref}
                      ]}

      :ok = :gen_tcp.send(sock, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
      Process.sleep(:infinity)
    end)

    {:ok, conn} = Mint.HTTP1.connect(:http, "localhost", port)

    {:ok, conn, ref} =
      Mint.HTTP1.request(
        conn,
        "GET",
        "/hello",
        [{"content-length", "3"}],
        "foo"
      )

    assert [
             {:status, ^ref, 200},
             {:headers, ^ref,
              [
                {"content-length", "2"}
              ]},
             {:data, ^ref, "ok"},
             {:done, ^ref}
           ] =
             mint_recv(conn)
  end

  test "http1 ssl - client", %{ssl_options: ssl_options} do
    port = 8000

    start_supervised!(
      {Bandit,
       plug: &hello/2,
       scheme: :https,
       port: port,
       startup_log: false,
       http_2_options: [enabled: false],
       thousand_island_options: [transport_options: ssl_options]}
    )

    {:ok, sock} =
      :ssl.connect(~c"localhost", port,
        mode: :binary,
        active: true,
        verify: :verify_none,
        packet: {&HTTP1.decode/2, :response}
      )

    :ok = :ssl.send(sock, "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")

    assert_receive {:http, ^sock,
                    [
                      {:status, ref, 200},
                      {:headers, ref, _},
                      {:data, ref, "hello from bandit\n"},
                      {:done, ref}
                    ]}
  end

  test "http1 ssl - server", %{ssl_options: ssl_options} do
    port = 8000

    {:ok, sock} =
      :ssl.listen(
        port,
        [
          mode: :binary,
          active: true,
          reuseaddr: true,
          verify: :verify_none,
          packet: {&HTTP1.decode/2, :request}
        ] ++ ssl_options
      )

    Task.start_link(fn ->
      {:ok, sock} = :ssl.transport_accept(sock)
      {:ok, sock} = :ssl.handshake(sock)

      assert_receive {:http, ^sock,
                      [
                        {:request, ref, :GET, "/hello"},
                        {:headers, ref,
                         [
                           {"host", "localhost:" <> _},
                           {"user-agent", "mint/" <> _},
                           {"content-length", "3"}
                         ]},
                        {:data, ref, "foo"},
                        {:done, ref}
                      ]}

      :ssl.send(sock, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
      Process.sleep(:infinity)
    end)

    {:ok, conn} =
      Mint.HTTP1.connect(
        :https,
        "localhost",
        port,
        transport_opts: [verify: :verify_none]
      )

    {:ok, conn, ref} =
      Mint.HTTP1.request(
        conn,
        "GET",
        "/hello",
        [{"content-length", "3"}],
        "foo"
      )

    assert [
             {:status, ^ref, 200},
             {:headers, ^ref, _},
             {:data, ^ref, "ok"},
             {:done, ^ref}
           ] =
             mint_recv(conn)
  end

  test "http2 - client", %{ssl_options: ssl_options} do
    port = 8000

    start_supervised!(
      {Bandit,
       plug: &hello/2,
       scheme: :https,
       port: port,
       startup_log: false,
       thousand_island_options: [transport_options: ssl_options]}
    )

    {:ok, sock} =
      :ssl.connect(~c"localhost", port,
        mode: :binary,
        active: true,
        verify: :verify_none,
        alpn_advertised_protocols: [<<"h2">>],
        packet: {&HTTP2.decode/2, {HPAX.new(4096), %{}}}
      )

    :ok =
      :ssl.send(sock, [
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        <<0::24, 4::8, 0::8, 0::1, 0::31>>
      ])

    # Receive until we get server SETTINGS
    assert_receive {:http, ^sock, [{:settings, []} | _]}

    # ACK server settings + send request
    :ok = :ssl.send(sock, <<0::24, 4::8, 1::8, 0::1, 0::31>>)

    headers = [
      {:store, ":method", "GET"},
      {:store, ":path", "/"},
      {:store, ":scheme", "https"},
      {:store, ":authority", "localhost"}
    ]

    {encoded, _} = HPAX.encode(headers, HPAX.new(4096))
    :ok = :ssl.send(sock, [<<IO.iodata_length(encoded)::24, 1::8, 5::8, 0::1, 1::31>>, encoded])

    assert_receive {:http, ^sock,
                    [
                      {:status, ref, 200},
                      {:headers, ref, _}
                    ]}

    assert_receive {:http, ^sock,
                    [
                      {:data, ^ref, "hello from bandit\n"},
                      {:done, ^ref}
                    ]}
  end

  test "http2 - server", %{ssl_options: ssl_options} do
    port = 8000

    {:ok, sock} =
      :ssl.listen(
        port,
        [
          mode: :binary,
          active: false,
          reuseaddr: true,
          verify: :verify_none,
          alpn_preferred_protocols: [<<"h2">>]
        ] ++ ssl_options
      )

    Task.start_link(fn ->
      {:ok, sock} = :ssl.transport_accept(sock)
      {:ok, sock} = :ssl.handshake(sock)

      # Send server SETTINGS
      :ok = :ssl.send(sock, <<0::24, 4::8, 0::8, 0::1, 0::31>>)

      # Read client connection preface (24-byte magic)
      {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(sock, 24)

      # Read h2 frames until we get HEADERS, extract stream_id
      stream_id =
        Enum.reduce_while(1..10, nil, fn _, _ ->
          {:ok, <<len::24, type::8, _flags::8, _::1, stream_id::31>>} = :ssl.recv(sock, 9)
          if len > 0, do: {:ok, _} = :ssl.recv(sock, len)

          if type == 1 do
            {:halt, stream_id}
          else
            {:cont, nil}
          end
        end)

      # ACK client settings
      :ok = :ssl.send(sock, <<0::24, 4::8, 1::8, 0::1, 0::31>>)

      # Send response HEADERS + DATA on same stream
      response_headers = [
        {:store, ":status", "200"},
        {:store, "content-type", "text/plain"}
      ]

      {encoded, _} = HPAX.encode(response_headers, HPAX.new(4096))

      :ok =
        :ssl.send(sock, [
          <<IO.iodata_length(encoded)::24, 1::8, 4::8, 0::1, stream_id::31>>,
          encoded
        ])

      body = "ok"
      :ok = :ssl.send(sock, [<<byte_size(body)::24, 0::8, 1::8, 0::1, stream_id::31>>, body])

      Process.sleep(:infinity)
    end)

    {:ok, conn} =
      Mint.HTTP2.connect(
        :https,
        "localhost",
        port,
        transport_opts: [verify: :verify_none]
      )

    {:ok, conn, ref} = Mint.HTTP2.request(conn, "GET", "/hello", [], nil)

    assert [
             {:status, ^ref, 200},
             {:headers, ^ref, _},
             {:data, ^ref, "ok"},
             {:done, ^ref}
           ] =
             mint_recv(conn)
  end

  defp mint_recv(conn) do
    mint_recv(conn, [], [])
  end

  defp mint_recv(conn, [], acc) do
    receive do
      msg ->
        {:ok, conn, parts} = Mint.HTTP.stream(conn, msg)
        mint_recv(conn, parts, acc)
    end
  end

  defp mint_recv(_conn, [{:done, _} = done | _], acc) do
    Enum.reverse([done | acc])
  end

  defp mint_recv(conn, [part | rest], acc) do
    mint_recv(conn, rest, [part | acc])
  end
end

defmodule HTTP1 do
  def decode(buffer, state) do
    decode(buffer, state, [])
  end

  defp decode(buffer, :request, acc) do
    case :erlang.decode_packet(:http_bin, buffer, []) do
      {:ok, {:http_request, method, uri, _ver}, rest} ->
        ref = make_ref()

        path =
          case uri do
            {:abs_path, p} -> p
            other -> other
          end

        decode(rest, {:headers, :request, ref}, [{:request, ref, method, path} | acc])

      {:more, _} = more ->
        flush(acc, buffer, :request, more)

      {:error, _} = err ->
        err
    end
  end

  defp decode(buffer, :response, acc) do
    case :erlang.decode_packet(:http_bin, buffer, []) do
      {:ok, {:http_response, _ver, status, _reason}, rest} ->
        ref = make_ref()
        decode(rest, {:headers, :response, ref}, [{:status, ref, status} | acc])

      {:more, _} = more ->
        flush(acc, buffer, :response, more)

      {:error, _} = err ->
        err
    end
  end

  defp decode(buffer, {:headers, reset, ref}, acc) do
    decode_headers(buffer, [], acc, reset, ref)
  end

  defp decode(buffer, {:body, reset, ref, n}, acc) do
    if byte_size(buffer) >= n do
      <<body::binary-size(n), rest::binary>> = buffer
      decode(rest, {:done, reset, ref}, [{:data, ref, body} | acc])
    else
      flush(acc, buffer, {:body, reset, ref, n}, {:more, n})
    end
  end

  defp decode(buffer, {:done, reset, ref}, acc) do
    {:ok, :http, Enum.reverse([{:done, ref} | acc]), buffer, reset}
  end

  defp decode_headers(buffer, headers, acc, reset, ref) do
    case :erlang.decode_packet(:httph_bin, buffer, []) do
      {:ok, {:http_header, _, _name, raw_name, value}, rest} ->
        decode_headers(rest, [{raw_name, value} | headers], acc, reset, ref)

      {:ok, :http_eoh, rest} ->
        headers = Enum.reverse(headers)
        content_length = content_length(headers)

        next_state =
          if content_length do
            {:body, reset, ref, content_length}
          else
            {:done, reset, ref}
          end

        decode(rest, next_state, [{:headers, ref, headers} | acc])

      {:more, _} = more ->
        flush(acc, buffer, {:headers, reset, ref}, more)

      {:error, _} = err ->
        err
    end
  end

  defp flush([], _buffer, _state, more) do
    more
  end

  defp flush(acc, buffer, state, _more) do
    {:ok, :http, Enum.reverse(acc), buffer, state}
  end

  defp content_length(headers) do
    case List.keyfind(headers, "content-length", 0) do
      {_, val} ->
        String.to_integer(val)

      nil ->
        nil
    end
  end
end

defmodule HTTP2 do
  import Bitwise

  def decode(buffer, state) do
    decode_frames(buffer, state, [])
  end

  defp decode_frames(buffer, state, acc) when byte_size(buffer) < 9 do
    flush(acc, buffer, state)
  end

  defp decode_frames(
         <<len::24, type::8, flags::8, _::1, stream_id::31, rest::binary>> = buffer,
         state,
         acc
       ) do
    if byte_size(rest) < len do
      flush(acc, buffer, state)
    else
      <<payload::binary-size(len), rest2::binary>> = rest
      {parts, state} = decode_frame(type, flags, stream_id, payload, state)
      decode_frames(rest2, state, Enum.reverse(parts) ++ acc)
    end
  end

  defp flush([], _buffer, _state), do: {:more, :undefined}

  defp flush(acc, buffer, state) do
    {:ok, :http, Enum.reverse(acc), buffer, state}
  end

  # SETTINGS
  defp decode_frame(0x4, flags, 0, payload, state) do
    if band(flags, 0x1) == 0x1 do
      {[{:settings_ack}], state}
    else
      {[{:settings, decode_settings(payload)}], state}
    end
  end

  # HEADERS
  defp decode_frame(0x1, flags, stream_id, payload, {hpax_ctx, refs}) do
    end_stream = band(flags, 0x1) == 0x1

    payload =
      if band(flags, 0x8) == 0x8 do
        <<pad::8, rest::binary>> = payload
        binary_part(rest, 0, byte_size(rest) - pad)
      else
        payload
      end

    header_block =
      if band(flags, 0x20) == 0x20 do
        <<_::1, _::31, _::8, rest::binary>> = payload
        rest
      else
        payload
      end

    {:ok, headers, hpax_ctx} = HPAX.decode(header_block, hpax_ctx)

    ref = make_ref()
    refs = Map.put(refs, stream_id, ref)

    # Extract :status pseudo-header
    {status, headers} =
      case List.keytake(headers, ":status", 0) do
        {{_, status}, rest} -> {String.to_integer(status), rest}
        nil -> {nil, headers}
      end

    parts = [{:status, ref, status}, {:headers, ref, headers}]

    parts =
      if end_stream do
        parts ++ [{:done, ref}]
      else
        parts
      end

    {parts, {hpax_ctx, refs}}
  end

  # DATA
  defp decode_frame(0x0, flags, stream_id, payload, {hpax_ctx, refs}) do
    end_stream = band(flags, 0x1) == 0x1
    ref = Map.fetch!(refs, stream_id)

    data =
      if band(flags, 0x8) == 0x8 do
        <<pad::8, rest::binary>> = payload
        binary_part(rest, 0, byte_size(rest) - pad)
      else
        payload
      end

    parts = [{:data, ref, data}]

    parts =
      if end_stream do
        parts ++ [{:done, ref}]
      else
        parts
      end

    refs =
      if end_stream do
        Map.delete(refs, stream_id)
      else
        refs
      end

    {parts, {hpax_ctx, refs}}
  end

  # WINDOW_UPDATE
  defp decode_frame(0x8, _flags, stream_id, <<_::1, increment::31>>, state) do
    {[{:window_update, stream_id, increment}], state}
  end

  # PING
  defp decode_frame(0x6, flags, 0, payload, state) do
    {[{:ping, payload, band(flags, 0x1) == 0x1}], state}
  end

  # GOAWAY
  defp decode_frame(0x7, _flags, 0, <<_::1, last::31, error::32, debug::binary>>, state) do
    {[{:goaway, last, error, debug}], state}
  end

  # Unknown frame
  defp decode_frame(type, flags, stream_id, payload, state) do
    {[{:frame, type, flags, stream_id, payload}], state}
  end

  defp decode_settings(<<>>) do
    []
  end

  defp decode_settings(<<id::16, value::32, rest::binary>>) do
    [{id, value} | decode_settings(rest)]
  end
end

ExUnit.run()
