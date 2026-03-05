# frozen_string_literal: true

require 'base64'
require 'jwt'
require 'net/http'
require 'omniauth-oauth2'
require 'openssl'
require 'securerandom'
require 'uri'

module OmniAuth
  module Strategies
    # OmniAuth strategy for Sign in with Apple.
    class Apple2 < OmniAuth::Strategies::OAuth2
      ISSUER = 'https://appleid.apple.com'
      JWKS_URL = 'https://appleid.apple.com/auth/keys'

      option :name, 'apple2'
      option :authorize_options, %i[scope state response_mode response_type nonce]
      option :scope, 'email name'
      option :response_mode, 'form_post'
      option :response_type, 'code'
      option :authorized_client_ids, []

      option :client_options,
             site: ISSUER,
             authorize_url: '/auth/authorize',
             token_url: '/auth/token',
             auth_scheme: :request_body,
             connection_opts: {
               headers: {
                 user_agent: 'icoretech-omniauth-apple2 gem',
                 accept: 'application/json'
               }
             }

      uid { id_info['sub'] }

      info do
        {
          name: full_name,
          email: id_info['email'],
          first_name: user_info.dig('name', 'firstName'),
          last_name: user_info.dig('name', 'lastName'),
          email_verified: true_claim?(id_info['email_verified']),
          is_private_email: true_claim?(id_info['is_private_email'])
        }.compact
      end

      credentials do
        {
          'token' => access_token.token,
          'refresh_token' => access_token.refresh_token,
          'expires_at' => access_token.expires_at,
          'expires' => access_token.expires?,
          'scope' => token_scope
        }.compact
      end

      extra do
        {
          'raw_info' => {
            'id_info' => id_info,
            'user_info' => user_info,
            'id_token' => raw_id_token
          }.compact
        }
      end

      def authorize_params
        super.tap do |params|
          params[:response_mode] ||= options[:response_mode]
          params[:response_type] ||= options[:response_type]
          params[:scope] ||= options[:scope]
          params[:nonce] ||= new_nonce
        end
      end

      def callback_url
        options[:callback_url] || options[:redirect_uri] || super
      end

      def query_string
        return '' if request.params['code']

        super
      end

      def client
        ::OAuth2::Client.new(client_id, client_secret, deep_symbolize(options.client_options))
      end

      private

      def id_info
        @id_info ||= begin
          token = raw_id_token
          raise CallbackError.new(:id_token_missing, 'id_token is missing') if blank?(token)

          decode_and_verify_id_token(token)
        end
      end

      def user_info
        raw_user = request.params['user']
        return {} if blank?(raw_user)

        @user_info ||= JSON.parse(raw_user)
      rescue JSON::ParserError
        {}
      end

      def raw_id_token
        request.params['id_token'] || access_token&.params&.dig('id_token')
      end

      def full_name
        parts = [user_info.dig('name', 'firstName'), user_info.dig('name', 'lastName')].compact
        return parts.join(' ') unless parts.empty?

        id_info['email']
      end

      def token_scope
        token_params = access_token.respond_to?(:params) ? access_token.params : {}
        token_params['scope'] || (access_token['scope'] if access_token.respond_to?(:[]))
      end

      def decode_and_verify_id_token(token)
        jwk = fetch_jwk(extract_kid(token))
        payload = decode_payload(token, jwk)

        verify_nonce!(payload)

        payload
      rescue JSON::ParserError, ArgumentError, JWT::DecodeError => e
        raise CallbackError.new(:id_token_invalid, e.message)
      end

      def verify_nonce!(payload)
        return unless payload.key?('nonce')

        expected_nonce = stored_nonce
        return if payload['nonce'] == expected_nonce

        raise CallbackError.new(:id_token_nonce_invalid, 'nonce does not match')
      end

      def fetch_jwk(expected_kid)
        jwks = fetch_jwks_keys
        matching_key = jwks.find { |key| key['kid'] == expected_kid }
        raise CallbackError.new(:jwks_key_not_found, expected_kid) unless matching_key

        JWT::JWK.import(matching_key)
      rescue JSON::ParserError, SocketError, SystemCallError => e
        raise CallbackError.new(:jwks_fetch_failed, e.message)
      end

      def fetch_jwks_keys
        uri = URI(JWKS_URL)
        response = Net::HTTP.get_response(uri)
        raise CallbackError.new(:jwks_fetch_failed, response.code) unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body).fetch('keys', [])
      end

      def valid_audiences
        [options.client_id, *Array(options.authorized_client_ids)].compact
      end

      def extract_kid(token)
        header_segment = token.split('.').first
        decoded_header = Base64.urlsafe_decode64(pad_base64(header_segment))
        JSON.parse(decoded_header)['kid']
      end

      def decode_payload(token, jwk)
        payload, = JWT.decode(
          token,
          jwk.public_key,
          true,
          decode_options
        )
        payload
      end

      def decode_options
        {
          algorithms: ['RS256'],
          iss: ISSUER,
          verify_iss: true,
          aud: valid_audiences,
          verify_aud: true,
          verify_iat: true,
          verify_expiration: true
        }
      end

      def client_id
        options.client_id
      end

      def client_secret
        JWT.encode(client_secret_claims, private_key, 'ES256', client_secret_headers)
      end

      def private_key
        OpenSSL::PKey::EC.new(options.pem)
      end

      def client_secret_claims
        now = Time.now.to_i
        {
          iss: options.team_id,
          iat: now,
          exp: now + 60,
          aud: ISSUER,
          sub: client_id
        }
      end

      def client_secret_headers
        {
          kid: options.key_id
        }
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.urlsafe_base64(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def true_claim?(value)
        [true, 'true'].include?(value)
      end

      def blank?(value)
        value.nil? || (value.respond_to?(:empty?) && value.empty?)
      end

      def pad_base64(value)
        value + ('=' * ((4 - (value.length % 4)) % 4))
      end
    end

    # Backward-compatible strategy name for existing callback paths.
    class Apple < Apple2
      option :name, 'apple'
    end
  end
end

OmniAuth.config.add_camelization 'apple2', 'Apple2'
OmniAuth.config.add_camelization 'apple', 'Apple'
