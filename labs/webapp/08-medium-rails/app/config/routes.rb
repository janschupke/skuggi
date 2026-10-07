Rails.application.routes.draw do
  root "home#index"

  # Rails health endpoint (used by the compose healthcheck): GET /up -> 200.
  get "up" => "rails/health#show", as: :rails_health_check

  get  "login"  => "sessions#new"
  post "login"  => "sessions#create"
  delete "logout" => "sessions#destroy"
  get  "signup" => "users#new", as: :signup

  resources :users
  resources :notes

  # Admin-only ops panel; renders config/ops_credentials.yml.
  get "ops" => "ops#show"
end
