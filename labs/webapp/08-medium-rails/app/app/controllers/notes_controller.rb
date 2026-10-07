class NotesController < ApplicationController
  before_action :require_login

  def index
    @notes = Note.order(:id)
  end

  def show
    # VULN (G / IDOR): reads any note by id regardless of owner.
    @note = Note.find(params[:id])
  end
end
