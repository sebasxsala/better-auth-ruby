# frozen_string_literal: true

require "json"
require "securerandom"
require "stringio"

module BetterAuthStripeTestHelpers
  def build_auth(options = {})
    plugin_options = {
      subscription: subscription_options
    }.merge(options)
    plugin_options[:subscription] = subscription_options.merge(plugin_options[:subscription] || {}) if plugin_options[:subscription].is_a?(Hash)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: stripe_test_secret,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.stripe(plugin_options)
      ]
    )
  end

  def subscription_options
    {
      enabled: true,
      plans: [
        {name: "basic", price_id: "price_basic"},
        {name: "pro", price_id: "price_pro", annual_discount_price_id: "price_pro_year", limits: {projects: 10}, free_trial: {days: 14}}
      ]
    }
  end

  def sign_up_cookie(auth, email: "billing@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Billing User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_user(auth, data = {})
    auth.context.internal_adapter.create_user({email: "user-#{SecureRandom.hex(4)}@example.com", name: "User", emailVerified: true}.merge(data.transform_keys(&:to_s)))
  end

  def stripe_subscription(id:, customer: "cus_test", price_id: "price_pro", lookup_key: nil, status: "active", quantity: 1, current_period_start: 1_700_000_000, current_period_end: 1_700_086_400, cancel_at_period_end: false, cancel_at: nil, canceled_at: nil, ended_at: nil, trial_start: nil, trial_end: nil, metadata: {}, schedule: nil, interval: nil, extra_items: [])
    {
      id: id,
      customer: customer,
      status: status,
      schedule: schedule,
      cancel_at_period_end: cancel_at_period_end,
      cancel_at: cancel_at,
      canceled_at: canceled_at,
      ended_at: ended_at,
      trial_start: trial_start,
      trial_end: trial_end,
      metadata: metadata,
      items: {
        data: [
          {
            id: "si_#{id}",
            quantity: quantity,
            current_period_start: current_period_start,
            current_period_end: current_period_end,
            price: {id: price_id, lookup_key: lookup_key, recurring: {interval: interval}}
          }
        ] + extra_items
      }
    }
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def assert_untrusted_stripe_url
    error = assert_raises(BetterAuth::APIError) { yield }
    assert_equal 403, error.status_code
    assert_includes error.message, "Invalid"
  end

  def rack_env(method, path, raw_body:, headers: {})
    path_info, query_string = path.split("?", 2)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(raw_body),
      "CONTENT_TYPE" => "application/json",
      "CONTENT_LENGTH" => raw_body.bytesize.to_s
    }.merge(headers)
  end

  def stripe_test_secret
    self.class.const_defined?(:SECRET) ? self.class.const_get(:SECRET) : "phase-twelve-secret-with-enough-entropy-123"
  end

  class RawBodyWebhookVerifier
    attr_reader :payloads

    def initialize(expected_payload:, event:)
      @expected_payload = expected_payload
      @event = event
      @payloads = []
    end

    def construct_event_async(payload, signature, secret)
      payloads << payload
      raise "expected raw body string" unless payload.is_a?(String)
      raise "payload changed" unless payload == @expected_payload
      raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

      @event
    end
  end

  class FakeStripeClient
    attr_reader :customers, :checkout, :billing_portal, :subscriptions, :prices, :subscription_schedules
    attr_accessor :webhooks_adapter

    def initialize
      @customers = Customers.new
      @checkout = Checkout.new
      @billing_portal = BillingPortal.new
      @subscriptions = Subscriptions.new
      @webhooks = Webhooks.new
      @prices = Prices.new
      @subscription_schedules = SubscriptionSchedules.new
    end

    def webhooks
      webhooks_adapter || @webhooks
    end

    class Customers
      attr_accessor :search_error, :search_data, :list_data, :create_error
      attr_reader :created, :list_calls, :search_calls, :retrieve_data, :updated

      def initialize
        @created = []
        @list_calls = []
        @search_calls = []
        @list_data = []
        @retrieve_data = {}
        @updated = []
      end

      def create(params)
        raise create_error if create_error

        metadata = params[:metadata] || params["metadata"] || {}
        customer = {
          "id" => "cus_#{created.length + 1}",
          "email" => params[:email],
          "name" => params[:name],
          "metadata" => metadata,
          :metadata => metadata
        }.merge(params.except(:email, :name, :metadata))
        created << customer
        customer
      end

      def search(query:, **params)
        search_calls << {query: query}.merge(params)
        raise search_error if search_error

        {"data" => search_data || []}
      end

      def list(**params)
        list_calls << params
        data = list_data.select do |customer|
          params[:email].nil? || (customer[:email] || customer["email"]) == params[:email]
        end
        {"data" => data}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "deleted" => false, "name" => "Billing User"}
      end

      def update(id, params)
        updated << {id: id, params: params}
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end
    end

    class Checkout
      attr_accessor :retrieve_data, :retrieve_error
      attr_reader :created, :created_options

      def initialize
        @created = []
        @created_options = []
        @retrieve_data = {}
      end

      def sessions
        self
      end

      def create(params, options = nil)
        created << params
        created_options << (options || {})
        {"id" => "cs_test", "url" => "https://stripe.test/checkout", "subscription" => "checkout-subscription", "customer" => "cus_checkout"}
      end

      def retrieve(id)
        raise retrieve_error if retrieve_error

        retrieve_data[id]
      end
    end

    class Prices
      attr_accessor :list_result
      attr_reader :list_calls
      attr_reader :retrieve_data

      def initialize
        @list_calls = []
        @retrieve_data = {}
      end

      def list(params)
        list_calls << params
        list_result || {"data" => [{"id" => "price_lookup_123"}]}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "recurring" => {"usage_type" => "licensed"}}
      end
    end

    class BillingPortal
      attr_accessor :create_error
      attr_reader :created

      def initialize
        @created = []
      end

      def sessions
        self
      end

      def create(params)
        raise create_error if create_error

        created << params
        {"url" => "https://stripe.test/portal"}
      end
    end

    class SubscriptionSchedules
      attr_accessor :list_data, :create_result
      attr_reader :created, :updated, :released, :retrieve_data

      def initialize
        @created = []
        @updated = []
        @released = []
        @retrieve_data = {}
        @list_data = []
      end

      def create(params)
        created << params
        create_result || {
          "id" => "sched_1",
          "status" => "active",
          "phases" => [
            {
              "start_date" => 1_700_000_000,
              "end_date" => 1_700_086_400,
              "items" => [{"price" => "price_basic", "quantity" => 1}]
            }
          ]
        }
      end

      def update(id, params)
        updated << {id: id, params: params}
        {"id" => id}.merge(params.transform_keys(&:to_s))
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def release(id)
        released << id
        {"id" => id, "status" => "released"}
      end

      def list(**_params)
        {"data" => list_data}
      end
    end

    class Subscriptions
      attr_accessor :list_data, :update_result, :update_error
      attr_reader :updated, :retrieve_data

      def initialize
        @list_data = []
        @retrieve_data = {}
        @updated = []
      end

      def update(id, params = {})
        raise update_error if update_error

        updated << {id: id, params: params}
        update_result || {"id" => id, "status" => params[:cancel_at_period_end] ? "canceled" : "active"}
      end

      def retrieve(id)
        retrieve_data[id] || {"id" => id, "status" => "active"}
      end

      def list(**params)
        data = list_data.select do |subscription|
          params[:customer].nil? || (subscription[:customer] || subscription["customer"]) == params[:customer]
        end
        {"data" => data}
      end
    end

    class Webhooks
      attr_accessor :async, :async_event
      attr_reader :constructed_async_args, :constructed_sync_args

      def construct_event(payload, signature, secret)
        @constructed_sync_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        payload
      end

      def construct_event_async(payload, signature, secret)
        @constructed_async_args = ["payload", signature, secret]
        raise "invalid signature" unless signature == "valid" && secret == "whsec_test"

        return nil if async_event == false

        async_event || payload
      end
    end
  end
end
