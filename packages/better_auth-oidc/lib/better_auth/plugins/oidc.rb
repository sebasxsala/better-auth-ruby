# frozen_string_literal: true

require "base64"
require "cgi"
require "json"
require "jwt"
require "net/http"
require "openssl"
require "resolv"
require "securerandom"
require "time"
require "uri"
require "zlib"

require_relative "../sso/plugin/oidc_discovery"
require_relative "../sso/plugin/oidc_runtime"
