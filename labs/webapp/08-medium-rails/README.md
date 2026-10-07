# 08-medium-rails — TrackRails (webapp set)

A genuine **Rails 7** project tracker (`ruby:3.3`) on **Postgres 16**, plus a small internal
**ops/SSH pivot** host. **Intentionally insecure**, loopback-only (web `127.0.0.1:8508`,
pivot SSH `127.0.0.1:8608`). Theme: **lateral movement**. Covers: mass-assignment / IDOR
privilege escalation (G), credential reuse → SSH lateral movement (I), easy privesc on the
pivot (K).

The Rails app is a **committed minimal-but-real Rails application** (not `rails new` at build
time): `config/routes.rb`, `app/controllers/*`, `app/models/*`, ERB views, Active Record
migrations and `db/seeds.rb`. `bundle install` runs at build; schema + seed load via
`bin/rails db:prepare` on first boot.

```sh
make lab-up      LAB=08-medium-rails
make lab-verify  LAB=08-medium-rails
uv run python labs/labctl scope 08-medium-rails --install
make lab-restore LAB=08-medium-rails
make lab-down    LAB=08-medium-rails
```

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
