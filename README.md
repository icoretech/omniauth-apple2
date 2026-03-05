# OmniAuth Apple2 Strategy

[![Test](https://github.com/icoretech/omniauth-apple2/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/icoretech/omniauth-apple2/actions/workflows/test.yml?query=branch%3Amain)
[![Gem Version](https://img.shields.io/gem/v/omniauth-apple2.svg)](https://rubygems.org/gems/omniauth-apple2)

`omniauth-apple2` provides a Sign in with Apple OAuth2 strategy for OmniAuth.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-apple2'
```

Then run:

```bash
bundle install
```

## Usage

Configure OmniAuth in your Rack/Rails app:

```ruby
use OmniAuth::Builder do
  # Second positional arg is intentionally nil:
  # client secret is generated internally from team_id/key_id/pem.
  provider :apple,
           ENV.fetch('APPLE_CLIENT_ID'),
           nil,
           team_id: ENV.fetch('APPLE_TEAM_ID'),
           key_id: ENV.fetch('APPLE_KEY_ID'),
           pem: ENV.fetch('APPLE_PRIVATE_KEY_PEM').gsub('\\n', "\n")
end
```

`provider :apple2` is also supported. `provider :apple` exists for drop-in compatibility.

## Apple Key PEM Handling

Apple private keys are often stored in env vars with escaped newlines (`\\n`), which Ruby/OpenSSL cannot parse as a valid PEM until you normalize them.

Use this pattern:

```ruby
pem: ENV.fetch('APPLE_PRIVATE_KEY_PEM').gsub('\\n', "\n")
```

If your secret manager supports multiline values, store the key as real multiline text and pass it directly without `gsub`.

Common parsing failures caused by unnormalized keys:

- `OpenSSL::PKey::ECError`
- `Neither PUB key nor PRIV key`
- `invalid curve name`

## Provider App Setup

- Apple Developer docs (Sign in with Apple REST API): <https://developer.apple.com/documentation/signinwithapplerestapi>
- Register callback URL (example): `https://your-app.example.com/auth/apple/callback`

## Options

- `scope`: default `email name`
- `response_mode`: default `form_post`
- `response_type`: default `code`
- `authorized_client_ids`: additional accepted `aud` values for `id_token` verification
- `callback_url` / `redirect_uri`: force exact redirect URI for token exchange

## Auth Hash

Example payload from `request.env['omniauth.auth']` (real flow shape, anonymized):

```json
{
  "uid": "apple-user-id",
  "info": {
    "name": "Sample User",
    "email": "sample@example.test",
    "first_name": "Sample",
    "last_name": "User",
    "email_verified": true,
    "is_private_email": false
  },
  "credentials": {
    "token": "sample-access-token",
    "refresh_token": "sample-refresh-token",
    "expires": true,
    "expires_at": 1773000000,
    "scope": "email name"
  },
  "extra": {
    "raw_info": {
      "id_info": {
        "sub": "apple-user-id",
        "aud": "com.example.web",
        "iss": "https://appleid.apple.com",
        "email": "sample@example.test"
      },
      "user_info": {
        "name": {
          "firstName": "Sample",
          "lastName": "User"
        }
      },
      "id_token": "sample-id-token"
    }
  }
}
```

## Ruby and Rails Compatibility

- Ruby: `>= 3.2`
- Rails integration lanes in CI: `7.1`, `7.2`, `8.0`, `8.1`

## Development

```bash
bundle install
bundle exec rake lint test_unit
RAILS_VERSION='~> 8.1.0' bundle exec rake test_rails_integration
```

## License

MIT
