FROM ruby:3.3-slim

# Build deps for the pg gem + a runtime curl for the healthcheck + psql client.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libpq-dev libyaml-dev git curl postgresql-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install gems first for layer caching. Gemfile.lock is generated on build.
COPY Gemfile ./
RUN bundle install

# App source.
COPY . /app
RUN chmod +x /app/entrypoint.sh /app/bin/rails \
 && mkdir -p /app/tmp/pids /app/log

EXPOSE 3000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["bin/rails", "server", "-b", "0.0.0.0", "-p", "3000"]
