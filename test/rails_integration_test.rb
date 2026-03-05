# frozen_string_literal: true

require_relative 'test_helper'

require 'action_controller/railtie'
require 'cgi'
require 'json'
require 'jwt'
require 'logger'
require 'rack/test'
require 'rails'
require 'uri'
require 'webmock/minitest'

class RailsIntegrationSessionsController < ActionController::Base
  def create
    auth = request.env.fetch('omniauth.auth')
    render json: {
      uid: auth['uid'],
      name: auth.dig('info', 'name'),
      email: auth.dig('info', 'email'),
      credentials: auth['credentials']
    }
  end

  def failure
    render json: { error: params[:message] }, status: :unauthorized
  end
end

class RailsIntegrationApp < Rails::Application
  config.root = File.expand_path('..', __dir__)
  config.eager_load = false
  config.secret_key_base = 'apple2-rails-integration-test-secret-key'
  config.active_support.cache_format_version = 7.1 if config.active_support.respond_to?(:cache_format_version=)

  if config.active_support.respond_to?(:to_time_preserves_timezone=) &&
     Rails.gem_version < Gem::Version.new('8.1.0')
    config.active_support.to_time_preserves_timezone = :zone
  end
  config.hosts.clear
  config.hosts << 'example.org'
  config.logger = Logger.new(nil)

  TEST_CLIENT_SECRET_EC_KEY = OpenSSL::PKey::EC.generate('prime256v1')
  TEST_ID_TOKEN_RSA_KEY = OpenSSL::PKey::RSA.generate(2048)
  TEST_JWK = JWT::JWK.new(TEST_ID_TOKEN_RSA_KEY.public_key).export.tap do |key|
    key.delete(:kid)
    key['kid'] = 'integration-kid'
  end

  config.middleware.use OmniAuth::Builder do
    provider :apple2,
             'com.example.web',
             '',
             team_id: 'TEAMID123',
             key_id: 'KEYID123',
             pem: TEST_CLIENT_SECRET_EC_KEY.to_pem,
             callback_url: 'https://example.org/auth/apple2/callback'
  end

  routes.append do
    match '/auth/:provider/callback', to: 'rails_integration_sessions#create', via: %i[get post]
    get '/auth/failure', to: 'rails_integration_sessions#failure'
  end
end

RailsIntegrationApp.initialize! unless RailsIntegrationApp.initialized?

class RailsIntegrationTest < Minitest::Test
  include Rack::Test::Methods

  def setup
    super
    @previous_test_mode = OmniAuth.config.test_mode
    @previous_allowed_request_methods = OmniAuth.config.allowed_request_methods
    @previous_request_validation_phase = OmniAuth.config.request_validation_phase

    OmniAuth.config.test_mode = false
    OmniAuth.config.allowed_request_methods = [:post]
    OmniAuth.config.request_validation_phase = nil
  end

  def teardown
    OmniAuth.config.test_mode = @previous_test_mode
    OmniAuth.config.allowed_request_methods = @previous_allowed_request_methods
    OmniAuth.config.request_validation_phase = @previous_request_validation_phase
    WebMock.reset!
    super
  end

  def app
    RailsIntegrationApp
  end

  def test_rails_request_and_callback_flow_returns_expected_auth_payload
    stub_apple_token_exchange
    stub_apple_jwks

    post '/auth/apple2'

    assert_equal 302, last_response.status

    authorize_uri = URI.parse(last_response['Location'])

    assert_equal 'appleid.apple.com', authorize_uri.host
    state = CGI.parse(authorize_uri.query).fetch('state').first
    nonce = CGI.parse(authorize_uri.query).fetch('nonce').first

    post '/auth/apple2/callback', callback_params(state, nonce)

    assert_equal 200, last_response.status

    payload = JSON.parse(last_response.body)

    assert_equal 'apple-user-id', payload['uid']
    assert_equal 'Sample User', payload['name']
    assert_equal 'sample@example.test', payload['email']
    assert_equal 'access-token', payload.dig('credentials', 'token')
    assert_equal 'refresh-token', payload.dig('credentials', 'refresh_token')
    assert_equal 'email name', payload.dig('credentials', 'scope')
    assert(payload.dig('credentials', 'expires'))

    assert_requested :post, 'https://appleid.apple.com/auth/token', times: 1
    assert_requested :get, 'https://appleid.apple.com/auth/keys', times: 1
  end

  private

  def callback_params(state, nonce)
    {
      code: 'oauth-test-code',
      state: state,
      id_token: JWT.encode(
        {
          sub: 'apple-user-id',
          aud: 'com.example.web',
          iss: 'https://appleid.apple.com',
          iat: Time.now.to_i,
          exp: Time.now.to_i + 300,
          email: 'sample@example.test',
          email_verified: 'true',
          is_private_email: 'false',
          nonce: nonce
        },
        RailsIntegrationApp::TEST_ID_TOKEN_RSA_KEY,
        'RS256',
        { kid: 'integration-kid' }
      ),
      user: {
        name: {
          firstName: 'Sample',
          lastName: 'User'
        }
      }.to_json
    }
  end

  def stub_apple_token_exchange
    stub_request(:post, 'https://appleid.apple.com/auth/token').to_return(
      status: 200,
      headers: { 'Content-Type' => 'application/json' },
      body: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        scope: 'email name',
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: 'returned-id-token-not-used'
      }.to_json
    )
  end

  def stub_apple_jwks
    stub_request(:get, 'https://appleid.apple.com/auth/keys').to_return(
      status: 200,
      headers: { 'Content-Type' => 'application/json' },
      body: {
        keys: [RailsIntegrationApp::TEST_JWK]
      }.to_json
    )
  end
end
