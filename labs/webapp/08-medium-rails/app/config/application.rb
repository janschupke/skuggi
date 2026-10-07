require_relative "boot"

require "logger" # guard concurrent-ruby/Ruby 3.3 load-order (uninitialized Logger)
require "rails"
# Only the frameworks this lab actually uses (no asset pipeline / mailer).
require "active_model/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module TrackRails
  class Application < Rails::Application
    config.load_defaults 7.1

    # Minimal, no-asset app: render ERB directly, no sprockets/importmap.
    config.api_only = false

    # VULN-ADJACENT (lab convenience): forgery protection is off so the
    # mass-assignment / IDOR vectors are cleanly reproducible with curl.
    config.action_controller.allow_forgery_protection = false

    # Keep logs on stdout for `docker logs`.
    config.logger = Logger.new($stdout)
    config.log_level = :info

    config.eager_load = false
    config.secret_key_base = "trackrails-dev-secret-key-base-do-not-use-in-prod"
  end
end
