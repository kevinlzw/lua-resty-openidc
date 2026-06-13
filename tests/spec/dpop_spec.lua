local http = require("socket.http")
local json = require("dkjson")
local mime = require("mime")
local sha2 = require("sha2")
local test_support = require("test_support")
require 'busted.runner'()

local dpop_public_jwk = {
  kty = "EC",
  crv = "P-256",
  x = "54-lhsmIsmguHg4xLmPhng5pMmuV5KOQlx4ntEEXpIE",
  y = "snSphjPmyBR6c_inWxgVH3n1F94-GMIzzj8wuzu0kBc",
}

local dpop_opts = {
  use_dpop = true,
  dpop_signing_alg = "ES256",
  dpop_private_key = test_support.load("/spec/private_ec_key.pem"),
  dpop_public_jwk = dpop_public_jwk,
}

local function b64url_decode(value)
  value = value:gsub("-", "+"):gsub("_", "/")
  local padding = #value % 4
  if padding > 0 then
    value = value .. string.rep("=", 4 - padding)
  end
  return mime.unb64(value)
end

local function b64url(value)
  return mime.b64(value):gsub("+", "-"):gsub("/", "_"):gsub("=", "")
end

local function decode_jwt(jwt)
  local header, payload = jwt:match("^([^.]+)%.([^.]+)%.")
  assert.truthy(header)
  assert.truthy(payload)
  return json.decode(b64url_decode(header)), json.decode(b64url_decode(payload))
end

local function logged_dpop_header(prefix)
  local log = test_support.load("/tmp/server/logs/error.log")
  return log:match(prefix .. " dpop header: ([^\n]+)")
end

local function logged_dpop_headers(prefix)
  local headers = {}
  local log = test_support.load("/tmp/server/logs/error.log")
  for header in log:gmatch(prefix .. " dpop header: ([^\n]+)") do
    table.insert(headers, header)
  end
  return headers
end

local function expected_ath(access_token)
  return b64url(sha2.bytes(access_token))
end

describe("when DPoP is enabled", function()
  local token_header, token_payload, userinfo_header, userinfo_payload

  setup(function()
    test_support.start_server({
      oidc_opts = dpop_opts,
    })
    test_support.login()

    token_header, token_payload = decode_jwt(logged_dpop_header("token"))
    userinfo_header, userinfo_payload = decode_jwt(logged_dpop_header("userinfo"))
  end)

  teardown(test_support.stop_server)

  it("adds a DPoP proof to the token endpoint call", function()
    assert.error_log_contains("DPoP proof header added to token endpoint call")
    assert.are.equals("dpop+jwt", token_header.typ)
    assert.are.equals("ES256", token_header.alg)
    assert.are.same(dpop_public_jwk, token_header.jwk)
    assert.are.equals("POST", token_payload.htm)
    assert.are.equals("http://127.0.0.1/token", token_payload.htu)
    assert.truthy(token_payload.jti)
    assert.truthy(token_payload.iat)
    assert.is_nil(token_payload.ath)
  end)

  it("uses a DPoP-bound authorization header for userinfo", function()
    assert.error_log_contains("userinfo authorization header: DPoP a_token")
    assert.error_log_contains("DPoP proof header added to userinfo endpoint call")
    assert.are.equals("dpop+jwt", userinfo_header.typ)
    assert.are.equals("ES256", userinfo_header.alg)
    assert.are.equals("GET", userinfo_payload.htm)
    assert.are.equals("http://127.0.0.1/user-info", userinfo_payload.htu)
    assert.are.equals(expected_ath("a_token"), userinfo_payload.ath)
  end)
end)

describe("when the token endpoint requests a DPoP nonce", function()
  local token_headers, first_payload, second_payload

  setup(function()
    test_support.start_server({
      token_dpop_nonce_challenge = "true",
      oidc_opts = dpop_opts,
    })
    test_support.login()

    token_headers = logged_dpop_headers("token")
    _, first_payload = decode_jwt(token_headers[1])
    _, second_payload = decode_jwt(token_headers[2])
  end)

  teardown(test_support.stop_server)

  it("retries the token endpoint call with a nonce-bound DPoP proof", function()
    assert.error_log_contains("retrying token endpoint call with DPoP nonce")
    assert.are.equals(2, #token_headers)
    assert.is_nil(first_payload.nonce)
    assert.are.equals("token-nonce", second_payload.nonce)
  end)
end)

describe("when the userinfo endpoint requests a DPoP nonce", function()
  local userinfo_headers, first_payload, second_payload

  setup(function()
    test_support.start_server({
      userinfo_dpop_nonce_challenge = "true",
      oidc_opts = dpop_opts,
    })
    test_support.login()

    userinfo_headers = logged_dpop_headers("userinfo")
    _, first_payload = decode_jwt(userinfo_headers[1])
    _, second_payload = decode_jwt(userinfo_headers[2])
  end)

  teardown(test_support.stop_server)

  it("retries the userinfo endpoint call with a nonce-bound DPoP proof", function()
    assert.error_log_contains("retrying userinfo endpoint call with DPoP nonce")
    assert.are.equals(2, #userinfo_headers)
    assert.is_nil(first_payload.nonce)
    assert.are.equals("userinfo-nonce", second_payload.nonce)
  end)
end)

describe("when DPoP is enabled and the access token is refreshed", function()
  setup(function()
    test_support.start_server({
      token_response_expires_in = 0,
      oidc_opts = dpop_opts,
    })

    local _, _, cookies = test_support.login()
    os.execute("sleep 1.5")
    http.request({
      url = "http://localhost/default/t",
      redirect = false,
      headers = { cookie = cookies },
    })
  end)

  teardown(test_support.stop_server)

  it("adds a DPoP proof to the refresh token request", function()
    assert.error_log_contains("request body for token endpoint call: .*grant_type=refresh_token.*")
    assert.error_log_contains("token dpop header: ey")
  end)
end)

describe("when DPoP is enabled without a private key", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_public_jwk = dpop_public_jwk,
      },
    })

    local _
    _, status = test_support.login()
  end)

  teardown(test_support.stop_server)

  it("fails with a clear error", function()
    assert.are.equals(401, status)
    assert.error_log_contains("authenticate failed: Can't use DPoP without opts.dpop_private_key")
  end)
end)

describe("when DPoP is enabled without a public JWK", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_private_key = test_support.load("/spec/private_ec_key.pem"),
      },
    })

    local _
    _, status = test_support.login()
  end)

  teardown(test_support.stop_server)

  it("fails with a clear error", function()
    assert.are.equals(401, status)
    assert.error_log_contains("authenticate failed: Can't use DPoP without opts.dpop_public_jwk")
  end)
end)

describe("when DPoP signing alg is not supported by discovery metadata", function()
  local status

  setup(function()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_private_key = test_support.load("/spec/private_ec_key.pem"),
        dpop_public_jwk = dpop_public_jwk,
        discovery = {
          dpop_signing_alg_values_supported = { "PS256" },
        }
      },
    })

    local _
    _, status = test_support.login()
  end)

  teardown(test_support.stop_server)

  it("fails with a clear error", function()
    assert.are.equals(401, status)
    assert.error_log_contains("authenticate failed: configured value for dpop_signing_alg %(ES256%) NOT found in dpop_signing_alg_values_supported in metadata")
  end)
end)
