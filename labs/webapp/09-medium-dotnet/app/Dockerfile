# NetLedger — multi-stage build: SDK compiles, aspnet runs.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore first (cached layer) then publish.
COPY NetLedger.csproj ./
RUN dotnet restore
COPY . ./
RUN dotnet publish NetLedger.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# curl for the compose healthcheck; iputils-ping so the "diagnostics" feature
# actually pings (the command-injection sink works with or without it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish ./

# Runtime-only files the publish step does not emit: the planted secrets file
# (path-traversal target) and the legitimate billing reports.
COPY appsettings.Secrets.json ./
COPY reports ./reports

# .NET 8 aspnet images default to port 8080; make it explicit.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "NetLedger.dll"]
