# frozen_string_literal: true

module BetterAuthAdapterContract
  def test_adapter_contract_crud_where_update_delete_and_counts
    config = contract_config(
      user: {
        additional_fields: {
          age: {type: "number", required: false},
          nickname: {type: "string", required: false}
        }
      }
    )

    with_contract_adapter(config) do |adapter|
      first = adapter.create(model: "user", data: {name: "Ada Lovelace", email: "ada@example.com", age: 25}, force_allow_id: false)
      second = adapter.create(model: "user", data: {name: "Grace Hopper", email: "grace@example.com", age: 30}, force_allow_id: false)
      adapter.update(model: "user", where: [{field: "id", value: second.fetch("id")}], update: {emailVerified: true})

      assert_kind_of String, first.fetch("id")
      assert_equal false, first.fetch("emailVerified")
      assert_equal ["ada@example.com"], adapter.find_many(model: "user", where: [{field: "emailVerified", value: false}]).map { |user| user.fetch("email") }
      assert_equal ["ada@example.com"], adapter.find_many(model: "user", where: [{field: "email", value: "ADA@EXAMPLE.COM", mode: "insensitive"}]).map { |user| user.fetch("email") }
      assert_equal ["ada@example.com"], adapter.find_many(model: "user", where: [{field: "name", operator: "contains", value: "love", mode: "insensitive"}]).map { |user| user.fetch("email") }
      assert_equal ["ada@example.com"], adapter.find_many(model: "user", where: [{field: "age", value: "25"}]).map { |user| user.fetch("email") }
      assert_equal 2, adapter.count(model: "user", where: [{field: "email", operator: "contains", value: "@example.com"}])

      updated_count = adapter.update_many(model: "user", where: [{field: "email", operator: "contains", value: "@example.com"}], update: {image: "avatar.png"})
      assert_equal 2, updated_count
      assert_equal ["avatar.png", "avatar.png"], adapter.find_many(model: "user", sort_by: {field: "email", direction: "asc"}).map { |user| user.fetch("image") }

      assert_equal 1, adapter.delete_many(model: "user", where: [{field: "id", value: second.fetch("id")}])
      assert_equal 1, adapter.count(model: "user")
      assert_nil adapter.find_one(model: "user", where: [{field: "id", value: second.fetch("id")}])
    end
  end

  def test_adapter_contract_transaction_rolls_back
    config = contract_config

    with_contract_adapter(config) do |adapter|
      user = adapter.create(model: "user", data: {name: "Ada", email: "rollback@example.com"})

      assert_raises(RuntimeError) do
        adapter.transaction do |trx|
          trx.update(model: "user", where: [{field: "id", value: user.fetch("id")}], update: {name: "Rolled Back"})
          raise "rollback"
        end
      end

      assert_equal "Ada", adapter.find_one(model: "user", where: [{field: "id", value: user.fetch("id")}]).fetch("name")
    end
  end

  def test_adapter_contract_json_array_fields_round_trip
    plugin = BetterAuth::Plugin.new(
      id: "typed-contract",
      schema: {
        typedRecord: {
          model_name: "typed_contract_records",
          fields: {
            id: {type: "string", required: true},
            metadata: {type: "json", required: false},
            tags: {type: "string[]", required: false},
            scores: {type: "number[]", required: false}
          }
        }
      }
    )
    config = contract_config(plugins: [plugin])

    with_contract_adapter(config) do |adapter|
      adapter.create(
        model: "typedRecord",
        data: {
          id: "typed-1",
          metadata: {"nested" => {"enabled" => true}},
          tags: ["alpha", "beta"],
          scores: [1, 2, 3]
        },
        force_allow_id: true
      )

      record = adapter.find_one(model: "typedRecord", where: [{field: "id", value: "typed-1"}])
      assert_equal({"nested" => {"enabled" => true}}, record.fetch("metadata"))
      assert_equal ["alpha", "beta"], record.fetch("tags")
      assert_equal [1, 2, 3], record.fetch("scores")
    end
  end

  def test_adapter_contract_join_session_user
    config = contract_config

    with_contract_adapter(config) do |adapter|
      user = adapter.create(model: "user", data: {name: "Join User", email: "join@example.com"})
      session = adapter.create(
        model: "session",
        data: {userId: user.fetch("id"), token: "join-token", expiresAt: Time.now + 3600},
        force_allow_id: true
      )

      found = adapter.find_one(model: "session", where: [{field: "token", value: session.fetch("token")}], join: {user: true})

      assert_equal "join-token", found.fetch("token")
      assert_equal user.fetch("id"), found.fetch("user").fetch("id")
      assert_equal "join@example.com", found.fetch("user").fetch("email")
    end
  end

  def test_adapter_contract_database_rate_limit_persists_throttles_and_resets
    config = contract_config(rate_limit: {storage: "database"})

    with_contract_adapter(config) do |adapter|
      auth = BetterAuth.auth(
        base_url: "http://localhost:3000",
        secret: self.class::SECRET,
        database: adapter,
        rate_limit: {enabled: true, window: 60, max: 1, storage: "database"},
        plugins: [
          {
            id: "contract-rate-limit",
            endpoints: {
              limited: BetterAuth::Endpoint.new(path: "/limited", method: "GET") { {ok: true} }
            }
          }
        ]
      )

      assert_equal 200, auth.call(contract_rack_env("GET", "/api/auth/limited")).first
      stored = adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/limited"}])
      assert_equal 1, stored.fetch("count")
      assert_kind_of Integer, stored.fetch("lastRequest")

      status, headers, body = auth.call(contract_rack_env("GET", "/api/auth/limited"))
      assert_equal 429, status
      assert_match(/\A\d+\z/, headers.fetch("x-retry-after"))
      assert_equal({"message" => "Too many requests. Please try again later."}, JSON.parse(body.join))

      adapter.update(
        model: "rateLimit",
        where: [{field: "key", value: "127.0.0.1|/limited"}],
        update: {count: 1, lastRequest: ((Time.now.to_f - 61) * 1000).to_i}
      )
      assert_equal 200, auth.call(contract_rack_env("GET", "/api/auth/limited?nonce=1")).first
      reset = adapter.find_one(model: "rateLimit", where: [{field: "key", value: "127.0.0.1|/limited"}])
      assert_equal 1, reset.fetch("count")
    end
  end

  private

  def contract_config(**options)
    BetterAuth::Configuration.new({secret: self.class::SECRET, database: :memory}.merge(options))
  end

  def contract_rack_env(method, path)
    path_info, query_string = path.split("?", 2)
    {
      "REQUEST_METHOD" => method,
      "PATH_INFO" => path_info,
      "QUERY_STRING" => query_string || "",
      "SERVER_NAME" => "localhost",
      "SERVER_PORT" => "3000",
      "REMOTE_ADDR" => "127.0.0.1",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new(""),
      "CONTENT_LENGTH" => "0"
    }
  end
end
