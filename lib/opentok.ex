defmodule OpenTok do
  @moduledoc """
  REST API wrapper to communicate with OpenTok signaling server.
  """

  require Logger

  use Tesla
  plug(Tesla.Middleware.Headers, [{"Accept", "application/json"}])
  plug(Tesla.Middleware.JSON, engine: Poison)

  @type opentok_response() :: {:json, map()} | {:error, Exception.t()}

  @endpoint "https://api.opentok.com"

  @default_role "subscriber"

  @default_ttl 60 * 5

  @token_prefix "T1=="

  @type project_config() :: %{api_key: String.t(), api_secret: String.t(), ttl: integer()}

  @doc """
  Create new WebRTC session.
  """
  @spec session_create(project_config()) :: opentok_response()
  def session_create(config) do
    {:ok, response} =
      post(
        @endpoint <> "/session/create",
        nil,
        headers: [{"X-OPENTOK-AUTH", jwt(config)}]
      )

    opentok_process_response(response)
  end

  @doc """
  Generate unique token to access session.
  """
  @spec generate_token(project_config(), String.t(), Keyword.t()) :: String.t()
  def generate_token(config, session_id, opts \\ []) do
    api_key = Map.fetch!(config, :api_key)
    api_secret = Map.fetch!(config, :api_secret)

    role = Keyword.get(opts, :role, @default_role)
    expire_time = Keyword.get(opts, :expire_time)
    connection_data = Keyword.get(opts, :connection_data)

    ts = :os.system_time(:seconds)

    nonce =
      :crypto.strong_rand_bytes(16)
      |> Base.encode16()

    data = [
      role: role,
      session_id: session_id,
      create_time: ts,
      nonce: nonce
    ]

    data = if expire_time, do: data ++ [expire_time: expire_time], else: data
    data = if connection_data, do: data ++ [connection_data: connection_data], else: data

    data_string = URI.encode_query(data)

    signature = sign_string(data_string, api_secret)

    @token_prefix <> Base.encode64("partner_id=#{api_key}&sig=#{signature}:#{data_string}")
  end

  @doc """
  Generate JWT to access OpenTok API services.
  """
  @spec jwt(project_config()) :: String.t()
  def jwt(config) do
    life_length = Map.get(config, :ttl, @default_ttl)
    salt = Base.encode16(:crypto.strong_rand_bytes(8))

    claims = %{
      iss: Map.fetch!(config, :api_key),
      ist: "project",
      iat: :os.system_time(:seconds),
      exp: :os.system_time(:seconds) + life_length,
      jti: salt
    }

    {_, jwt} =
      nil
      |> jose_jwk(config)
      |> JOSE.JWT.sign(jose_jws(%{}), claims)
      |> JOSE.JWS.compact()

    # { :ok, jwt, full_claims } = Guardian.encode_and_sign("smth", :access, claims)
    jwt
  end

  @spec opentok_process_response(Tesla.Env.t()) :: opentok_response()
  defp opentok_process_response(response) do
    case response do
      %{status: 200, body: body} ->
        {:json, body}

      _ ->
        Logger.error(fn -> "OpenTok query: #{inspect(response)}" end)
        {:error, OpenTok.ApiError}
    end
  end

  defp jose_jws(headers) do
    Map.merge(%{"alg" => hd(["HS256"])}, headers)
  end

  defp jose_jwk(the_secret = %JOSE.JWK{}, _config), do: the_secret
  defp jose_jwk(the_secret, _config) when is_binary(the_secret), do: JOSE.JWK.from_oct(the_secret)
  defp jose_jwk(the_secret, _config) when is_map(the_secret), do: JOSE.JWK.from_map(the_secret)
  defp jose_jwk({mod, fun}, config), do: jose_jwk(:erlang.apply(mod, fun, []), config)
  defp jose_jwk({mod, fun, args}, config), do: jose_jwk(:erlang.apply(mod, fun, args), config)
  defp jose_jwk(nil, config), do: jose_jwk(Map.fetch!(config, :api_secret), config)

  @spec sign_string(String.t(), String.t()) :: String.t()
  defp sign_string(string, secret) do
    :sha
    |> :crypto.hmac(secret, string)
    |> Base.encode16(case: :lower)
  end
end
