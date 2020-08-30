defmodule OpenTokTest do
  use ExUnit.Case
  doctest OpenTok

  @test_session_id "1_MX4xMjM0NTY3OH4-VGh1IEZlYiAyNyAwNDozODozMSBQU1QgMjAxNH4wLjI0NDgyMjI"
  @project_config %{
    api_key: "12345678",
    api_secret: "0123456789abcdef0123456789abcdef0123456789",
    ttl: 60 * 5
  }

  test "Check that JWT token is generated" do
    assert OpenTok.jwt(@project_config)
  end

  test "Generation of OpenTok session" do
    response = OpenTok.session_create(@project_config)
    {:json, [session]} = response
    assert session["session_id"]
  end

  test "Generation of token" do
    token = OpenTok.generate_token(@project_config, @test_session_id)
    assert token
  end
end
