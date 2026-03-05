# Test Matrix

`omniauth-apple2` is validated against:

- Ruby: `3.2`, `3.3`, `3.4`, `4.0`
- Rails integration lanes: `~> 7.1.0`, `~> 7.2.0`, `~> 8.0.0`, `~> 8.1.0`
- `omniauth-oauth2`: `1.8.x`

## Local Commands

```bash
bundle exec rake lint
bundle exec rake test_unit
bundle exec rake test_rails_integration
```

Run a specific Rails lane:

```bash
RAILS_VERSION='~> 8.1.0' bundle exec rake test_rails_integration
```
