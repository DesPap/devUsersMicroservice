FROM php:8.3.11

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    netcat-openbsd \
    zip \
    unzip \
    git \
    && docker-php-ext-install pdo pdo_pgsql

    # Install Composer
    COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
    
    WORKDIR /var/www/html

    # Copy all files from the current directory on the host to the working directory in the container
    COPY . .

    # Install Laravel Socialite and Passport
    RUN composer require laravel/socialite laravel/passport

    # Ensure proper ownership for Laravel directories
    RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

    # Make the wait-for-postgres.sh script executable
    RUN chmod +x /var/www/html/wait-for-db.sh

    # Set the wait-for-postgres.sh script as the entrypoint to wait for the database before starting the application
    ENTRYPOINT ["sh", "/var/www/html/wait-for-db.sh"]

    CMD [ "php", "artisan", "serve", "--host=0.0.0.0", "--port=8000" ]