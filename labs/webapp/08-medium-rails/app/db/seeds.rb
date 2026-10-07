# Seeded once on a fresh database (db:prepare on an empty volume; re-run on
# every `restore` because recreate drops the pgdata volume). Idempotent.

admin = User.find_or_create_by!(email: "admin@trackrails.lab") do |u|
  u.name = "Dana Ops"
  u.role = "admin"
  # The attacker is NOT expected to know/crack this — escalation is via the
  # mass-assignment flaw, not by logging in as admin.
  u.password = "A9f!q2Lx-admin-Zr7"
end

members = [
  { email: "alex@trackrails.lab",  name: "Alex Rivera",  password: "m3mber-alex-7731" },
  { email: "priya@trackrails.lab", name: "Priya Nair",   password: "m3mber-priya-5520" },
  { email: "sam@trackrails.lab",   name: "Sam Okafor",   password: "m3mber-sam-9142" },
]
members.each do |m|
  User.find_or_create_by!(email: m[:email]) do |u|
    u.name = m[:name]
    u.role = "member"
    u.password = m[:password]
  end
end

alex = User.find_by!(email: "alex@trackrails.lab")

Note.find_or_create_by!(title: "Sprint 14 — tracker backlog") do |n|
  n.user = alex
  n.body = "Groom the issue backlog; close stale tickets before the release."
end

Note.find_or_create_by!(title: "Ops handover") do |n|
  n.user = admin
  n.body = <<~BODY
    Release pipeline runs from the ops host (ops.trackrails.lab).
    Deploy credentials are kept in config/ops_credentials.yml — admin ops panel
    at /ops renders them. Rotate quarterly.
  BODY
end

puts "Seeded #{User.count} users and #{Note.count} notes."
