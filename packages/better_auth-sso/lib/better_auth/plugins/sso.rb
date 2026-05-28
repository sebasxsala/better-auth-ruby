# frozen_string_literal: true

require "base64"
require "cgi"
require "json"
require "net/http"
require "openssl"
require "rexml/document"
require "resolv"
require "securerandom"
require "time"
require "uri"
require "zlib"

require_relative "../sso/plugin/core"
require_relative "../sso/plugin/providers"
require_relative "../sso/plugin/sign_in_and_oidc_callbacks"
require_relative "../sso/plugin/endpoints"
require_relative "../sso/plugin/provider_utils"
