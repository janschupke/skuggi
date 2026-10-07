class User < ApplicationRecord
  has_secure_password
  has_many :notes, dependent: :destroy

  validates :email, presence: true, uniqueness: true

  # Roles: "member" (default) and "admin". The admin role gates the ops panel.
  def admin?
    role == "admin"
  end
end
