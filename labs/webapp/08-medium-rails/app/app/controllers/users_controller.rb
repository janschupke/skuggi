class UsersController < ApplicationController
  before_action :require_login, except: %i[new create]

  def index
    # Any signed-in user can enumerate the whole user book.
    @users = User.order(:id)
  end

  def show
    # VULN (G / IDOR): no ownership or authorization check — any logged-in user
    # can read ANY other user's record by walking /users/:id.
    @user = User.find(params[:id])
  end

  def new
    @user = User.new
  end

  def create
    # Self-service signup.
    @user = User.new(user_params)
    @user.role = "member" if @user.role.blank?
    if @user.save
      session[:user_id] = @user.id
      redirect_to user_path(@user), notice: "Account created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
    @user = User.find(params[:id])
  end

  def update
    # VULN (G / IDOR): finds by :id with NO check that it is the current user —
    # any member can update any account.
    @user = User.find(params[:id])
    if @user.update(user_params)
      redirect_to user_path(@user), notice: "Profile updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  private

  # VULN (G / mass assignment): params.permit! allows EVERY attribute through,
  # including :role. A member can PATCH user[role]=admin to escalate, then reach
  # the admin-only /ops panel.
  def user_params
    params.require(:user).permit!
  end
end
