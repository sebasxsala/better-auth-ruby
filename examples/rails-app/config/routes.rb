require "better_auth/rails"
require_relative "../../shared/lib/better_auth_examples"

ActionDispatch::Routing::Mapper.include BetterAuth::Rails::Routing

registry = BetterAuthExamples.registry(
  app_name: "Better Auth Rails Example",
  base_url: ENV.fetch("BETTER_AUTH_URL", "http://localhost:3000"),
  root_path: Rails.root.to_s
)
dynamic_auth = BetterAuthExamples::DynamicAuth.new(registry)
dashboard = BetterAuthExamples::DashboardApp.new(registry, framework_name: "Rails")

Rails.application.routes.draw do
  better_auth auth: dynamic_auth, at: "/api/auth"

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", :as => :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  get "/sessions", to: dashboard
  get "/social", to: dashboard
  get "/plugins", to: dashboard
  get "/database", to: dashboard
  get "/settings", to: dashboard

  mount dashboard, at: "/"
end
