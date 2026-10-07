class OpsController < ApplicationController
  before_action :require_login

  # Admin-only ops panel. Reaching this requires the privilege escalation from
  # the mass-assignment flaw (a normal "member" is bounced). It renders the
  # on-disk config/ops_credentials.yml, which leaks the reused deploy SSH
  # password (vector I: credential reuse -> SSH to ops.trackrails.lab).
  def show
    unless current_user&.admin?
      redirect_to(root_path, alert: "Admins only.") and return
    end
    @credentials = File.read(Rails.root.join("config", "ops_credentials.yml"))
  end
end
