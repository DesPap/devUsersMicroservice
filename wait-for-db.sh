# shebang for the os, about the interpreter to be used to execute the script(linux)
#!/bin/sh

echo "Waiting for the database to be ready..."

# environment variables for database host and port
DB_HOST=${DB_HOST:-postgres}
DB_PORT=${DB_PORT:-5432}

# a 90 seconds timeout, to avoid indefinite waiting for the database to become available
TIMEOUT=90
start_time=$(date +%s)

# check if the database is available
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
  
  current_time=$(date +%s)
  elapsed_time=$((current_time - start_time))

# if waiting for 90 seconds or more exit
  if [ $elapsed_time -ge $TIMEOUT ]; then
    echo "Timeout reached, database is still not available after $TIMEOUT seconds."
    exit 1
  fi
done

echo "Database is up and running!"

# Start the application by passing control back to Docker's CMD
exec "$@"