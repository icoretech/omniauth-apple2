# frozen_string_literal: true

require_relative 'test_helper'

require 'jwt'
require 'uri'
require 'webmock/minitest'

class OmniauthApple2Test < Minitest::Test
  def setup
    super
    WebMock.reset!
    @client_secret_ec_key = OpenSSL::PKey::EC.generate('prime256v1')
    @id_token_rsa_key = OpenSSL::PKey::RSA.generate(2048)
    @public_jwk = JWT::JWK.new(@id_token_rsa_key.public_key)
    @public_jwk[:kid] = 'test-kid'
  end

  def build_strategy
    OmniAuth::Strategies::Apple2.new(
      nil,
      'com.example.web',
      '',
      team_id: 'TEAMID123',
      key_id: 'KEYID123',
      pem: @client_secret_ec_key.to_pem
    )
  end

  def test_uses_current_apple_endpoints
    client_options = build_strategy.options.client_options

    assert_equal 'https://appleid.apple.com', client_options.site
    assert_equal '/auth/authorize', client_options.authorize_url
    assert_equal '/auth/token', client_options.token_url
  end

  def test_uid_info_and_extra_are_derived_from_id_token_and_user_param
    strategy = strategy_with_token_and_jwks(id_token_payload: {
                                              'sub' => 'apple-user-id',
                                              'aud' => 'com.example.web',
                                              'iss' => 'https://appleid.apple.com',
                                              'iat' => Time.now.to_i,
                                              'exp' => Time.now.to_i + 300,
                                              'email' => 'sample@example.test',
                                              'email_verified' => 'true',
                                              'is_private_email' => 'false'
                                            },
                                            user_payload: {
                                              'name' => { 'firstName' => 'Sample', 'lastName' => 'User' }
                                            })

    assert_equal 'apple-user-id', strategy.uid
    assert_equal(
      {
        name: 'Sample User',
        email: 'sample@example.test',
        first_name: 'Sample',
        last_name: 'User',
        email_verified: true,
        is_private_email: false
      },
      strategy.info
    )
    assert_equal 'apple-user-id', strategy.extra.dig('raw_info', 'id_info', 'sub')
  end

  def test_credentials_include_refresh_token_even_when_token_does_not_expire
    strategy = build_strategy
    token = FakeCredentialAccessToken.new(
      token: 'access-token',
      refresh_token: 'refresh-token',
      expires_at: nil,
      expires: false,
      params: { 'scope' => 'email name' }
    )

    strategy.define_singleton_method(:access_token) { token }

    assert_equal(
      {
        'token' => 'access-token',
        'refresh_token' => 'refresh-token',
        'expires' => false,
        'scope' => 'email name'
      },
      strategy.credentials
    )
  end

  def test_authorize_params_include_response_mode_response_type_and_nonce
    strategy = build_strategy
    strategy.define_singleton_method(:request) { Rack::Request.new(Rack::MockRequest.env_for('/auth/apple2')) }
    strategy.define_singleton_method(:session) { {} }

    params = strategy.authorize_params

    assert_equal 'form_post', params[:response_mode]
    assert_equal 'code', params[:response_type]
    assert_equal 'email name', params[:scope]
    refute_nil params[:nonce]
  end

  def test_raw_info_raises_when_id_token_is_missing
    strategy = build_strategy
    strategy.define_singleton_method(:access_token) { FakeAccessTokenWithoutIdToken.new }
    strategy.define_singleton_method(:request) { Rack::Request.new(Rack::MockRequest.env_for('/auth/apple2/callback?code=abc')) }

    assert_raises(OmniAuth::Strategies::OAuth2::CallbackError) { strategy.extra }
  end

  def test_request_phase_redirects_to_apple_with_expected_params
    previous_request_validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil

    app = ->(_env) { [404, { 'Content-Type' => 'text/plain' }, ['not found']] }
    strategy = OmniAuth::Strategies::Apple2.new(
      app,
      'com.example.web',
      '',
      team_id: 'TEAMID123',
      key_id: 'KEYID123',
      pem: @client_secret_ec_key.to_pem
    )
    env = Rack::MockRequest.env_for('/auth/apple2', method: 'POST')
    env['rack.session'] = {}

    status, headers, = strategy.call(env)

    assert_equal 302, status

    location = URI.parse(headers['Location'])
    params = URI.decode_www_form(location.query).to_h

    assert_equal 'appleid.apple.com', location.host
    assert_equal 'com.example.web', params.fetch('client_id')
    assert_equal 'form_post', params.fetch('response_mode')
    assert_equal 'code', params.fetch('response_type')
    assert_equal 'email name', params.fetch('scope')
  ensure
    OmniAuth.config.request_validation_phase = previous_request_validation_phase
  end

  private

  def strategy_with_token_and_jwks(id_token_payload:, user_payload: nil)
    strategy = build_strategy
    id_token = JWT.encode(id_token_payload, @id_token_rsa_key, 'RS256', { kid: 'test-kid' })

    token = FakeCredentialAccessToken.new(
      token: 'access-token',
      refresh_token: 'refresh-token',
      expires_at: Time.now.to_i + 3600,
      expires: true,
      params: { 'id_token' => id_token, 'scope' => 'email name' }
    )

    request_env = Rack::MockRequest.env_for('/auth/apple2/callback?code=abc')
    request_env['rack.session'] = {}
    request = Rack::Request.new(request_env)
    request.update_param('user', user_payload.to_json) if user_payload

    jwk_payload = @public_jwk.export
    jwk_payload.delete(:kid)
    jwk_payload['kid'] = 'test-kid'
    stub_request(:get, OmniAuth::Strategies::Apple2::JWKS_URL).to_return(
      status: 200,
      headers: { 'Content-Type' => 'application/json' },
      body: { keys: [jwk_payload] }.to_json
    )

    strategy.define_singleton_method(:request) { request }
    strategy.define_singleton_method(:session) { request_env['rack.session'] }
    strategy.define_singleton_method(:access_token) { token }
    strategy
  end

  class FakeAccessTokenWithoutIdToken
    def params
      {}
    end
  end

  class FakeCredentialAccessToken
    attr_reader :token, :refresh_token, :expires_at, :params

    def initialize(token:, refresh_token:, expires_at:, expires:, params:)
      @token = token
      @refresh_token = refresh_token
      @expires_at = expires_at
      @expires = expires
      @params = params
    end

    def expires?
      @expires
    end

    def [](key)
      { 'scope' => @params['scope'] }[key]
    end
  end
end
