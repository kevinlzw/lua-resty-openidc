local http = require("socket.http")
local json = require("dkjson")
local mime = require("mime")
local sha2 = require("sha2")
local test_support = require("test_support")
require 'busted.runner'()

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

local function assert_command(command)
  local ok = os.execute(command)
  assert.truthy(ok == true or ok == 0)
end

local function load_file(path)
  local file = assert(io.open(path, "rb"))
  local value = file:read("*a")
  file:close()
  return value
end

local function write_file(path, value)
  local file = assert(io.open(path, "wb"))
  file:write(value)
  file:close()
end

local function generate_dpop_opts()
  local prefix = "/tmp/dpop-spec-" .. tostring(math.random(1000000000))
  local private_key_path = prefix .. ".pem"
  local public_point_path = prefix .. ".pub"

  assert_command("openssl ecparam -name prime256v1 -genkey -noout -out " .. private_key_path)
  assert_command("openssl ec -in " .. private_key_path .. " -pubout -outform DER 2>/dev/null | openssl asn1parse -inform DER -strparse 23 -noout -out " .. public_point_path)

  local public_point = load_file(public_point_path)
  assert.are.equals(65, #public_point)
  assert.are.equals(string.char(4), public_point:sub(1, 1))

  return {
    use_dpop = true,
    dpop_signing_alg = "ES256",
    dpop_private_key = load_file(private_key_path),
    dpop_public_jwk = {
      kty = "EC",
      crv = "P-256",
      x = b64url(public_point:sub(2, 33)),
      y = b64url(public_point:sub(34, 65)),
    },
    discovery = {
      dpop_signing_alg_values_supported = { "ES256", "RS256", "PS256" },
    }
  }
end

local rsa_private_key = test_support.load("/spec/private_rsa_key.pem")
local rsa_public_key = test_support.load("/spec/public_rsa_key.pem")
local rsa_public_jwk = json.decode(test_support.load("/spec/rsa_key_jwk_with_n_and_e.json")).keys[1]

local function dpop_opts_with_rsa_alg(alg)
  return {
    use_dpop = true,
    dpop_signing_alg = alg,
    dpop_private_key = rsa_private_key,
    dpop_public_jwk = rsa_public_jwk,
    discovery = {
      dpop_signing_alg_values_supported = { "ES256", "RS256", "PS256" },
    }
  }
end

local function decode_jwt(jwt)
  jwt = test_support.trim(jwt)
  local header, payload, signature = jwt:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  if not header or not payload or not signature then
    error("could not parse JWT: " .. tostring(jwt))
  end
  return json.decode(b64url_decode(header)), json.decode(b64url_decode(payload)), header .. "." .. payload, b64url_decode(signature)
end

local function logged_dpop_header(prefix)
  local log = test_support.load("/tmp/server/logs/error.log")
  return log:match(prefix .. " dpop header: ([A-Za-z0-9_%-%.]+)")
end

local function logged_dpop_headers(prefix)
  local headers = {}
  local log = test_support.load("/tmp/server/logs/error.log")
  for header in log:gmatch(prefix .. " dpop header: ([A-Za-z0-9_%-%.]+)") do
    table.insert(headers, header)
  end
  return headers
end

local function expected_ath(access_token)
  return b64url(sha2.bytes(access_token))
end

local function verify_dpop_signature(jwt, public_key, alg)
  local _, _, signing_input, signature = decode_jwt(jwt)
  local prefix = "/tmp/dpop-verify-" .. tostring(math.random(1000000000))
  local public_key_path = prefix .. ".pem"
  local signing_input_path = prefix .. ".txt"
  local signature_path = prefix .. ".sig"

  write_file(public_key_path, public_key)
  write_file(signing_input_path, signing_input)
  write_file(signature_path, signature)

  local command = "openssl dgst -sha256 -verify " .. public_key_path .. " -signature " .. signature_path
  if alg == "PS256" then
    command = command .. " -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256"
  end
  command = command .. " " .. signing_input_path .. " >/dev/null"
  assert_command(command)
end

describe("when DPoP is enabled", function()
  local token_header, token_payload, userinfo_header, userinfo_payload
  local dpop_public_jwk

  setup(function()
    local dpop_opts = generate_dpop_opts()
    dpop_public_jwk = dpop_opts.dpop_public_jwk
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

describe("when DPoP is enabled with RS256", function()
  local token_header

  setup(function()
    test_support.start_server({
      oidc_opts = dpop_opts_with_rsa_alg("RS256"),
    })
    test_support.login()

    token_header = decode_jwt(logged_dpop_header("token"))
  end)

  teardown(test_support.stop_server)

  it("adds an RS256-signed DPoP proof to the token endpoint call", function()
    assert.are.equals("dpop+jwt", token_header.typ)
    assert.are.equals("RS256", token_header.alg)
    assert.are.same(rsa_public_jwk, token_header.jwk)
    verify_dpop_signature(logged_dpop_header("token"), rsa_public_key, "RS256")
  end)
end)

describe("when DPoP is enabled with PS256", function()
  local token_header

  setup(function()
    test_support.start_server({
      oidc_opts = dpop_opts_with_rsa_alg("PS256"),
    })
    test_support.login()

    local token_dpop_header = logged_dpop_header("token")
    assert.truthy(token_dpop_header)
    token_header = decode_jwt(token_dpop_header)
  end)

  teardown(test_support.stop_server)

  it("adds a PS256-signed DPoP proof to the token endpoint call", function()
    assert.are.equals("dpop+jwt", token_header.typ)
    assert.are.equals("PS256", token_header.alg)
    assert.are.same(rsa_public_jwk, token_header.jwk)
    verify_dpop_signature(logged_dpop_header("token"), rsa_public_key, "PS256")
  end)
end)

describe("when the token endpoint requests a DPoP nonce", function()
  local token_headers, first_payload, second_payload

  setup(function()
    test_support.start_server({
      token_dpop_nonce_challenge = "true",
      oidc_opts = generate_dpop_opts(),
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
      oidc_opts = generate_dpop_opts(),
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
      oidc_opts = generate_dpop_opts(),
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
    local dpop_opts = generate_dpop_opts()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_public_jwk = dpop_opts.dpop_public_jwk,
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
    local dpop_opts = generate_dpop_opts()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_private_key = dpop_opts.dpop_private_key,
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
    local dpop_opts = generate_dpop_opts()
    test_support.start_server({
      oidc_opts = {
        use_dpop = true,
        dpop_private_key = dpop_opts.dpop_private_key,
        dpop_public_jwk = dpop_opts.dpop_public_jwk,
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
