#!/bin/bash
# Apply database migrations from rota-infra

set -e

MIGRATIONS_DIR="../rota-infra/migrations"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-rota}"
POSTGRES_DB="${POSTGRES_DB:-rota_main}"

echo "🔧 Applying migrations to $POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DB"

# Function to apply migrations for a schema
apply_schema_migrations() {
    local schema=$1
    echo ""
    echo "📦 Applying $schema migrations..."
    
    for migration in "$MIGRATIONS_DIR/$schema"/*.sql; do
        if [ -f "$migration" ]; then
            echo "  ▶ $(basename "$migration")"
            PGPASSWORD="$POSTGRES_PASSWORD" psql \
                -h "$POSTGRES_HOST" \
                -p "$POSTGRES_PORT" \
                -U "$POSTGRES_USER" \
                -d "$POSTGRES_DB" \
                -f "$migration"
        fi
    done
}

# Apply migrations in order
apply_schema_migrations "auth"
apply_schema_migrations "courses"
apply_schema_migrations "learning"
apply_schema_migrations "ai"

echo ""
echo "✅ All migrations applied successfully!"
