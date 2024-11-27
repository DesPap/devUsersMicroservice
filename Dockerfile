FROM php:8.3.11

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    netcat-openbsd \
    zip \
    unzip \
    git \
    curl \
    # nodejs \
    # npm \
    && docker-php-ext-install pdo pdo_pgsql

    # Install Composer
    COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
    
    # Install Node.js and npm
    # RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    # apt-get install -y nodejs && \
    # corepack enable && \
    # corepack prepare npm@latest --activate

    RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest

    WORKDIR /var/www/html

    # Copy all files from the current directory on the host to the working directory in the container
    COPY . .

    # Install Laravel dependencies
    RUN composer install --no-dev --optimize-autoloader

    # Install Laravel Socialite and Passport
    RUN composer require laravel/socialite laravel/passport

    # Ensure proper permissions for Laravel directories
    RUN mkdir -p /var/www/html/public/build && \
    chown -R www-data:www-data /var/www/html/public /var/www/html/storage /var/www/html/bootstrap/cache && \
    chmod -R 775 /var/www/html/public /var/www/html/storage /var/www/html/bootstrap/cache

    # Install React dependencies and build the frontend
    WORKDIR /var/www/html/resources/js
    RUN npm install
    RUN npm run build

    # Return to the Laravel directory
    WORKDIR /var/www/html

    # Clear caches and optimize Laravel
    RUN php artisan config:cache
    RUN php artisan route:cache
    RUN php artisan view:cache

    # Ensure proper ownership for Laravel directories
    RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

    # Make the wait-for-postgres.sh script executable
    RUN chmod +x /var/www/html/wait-for-db.sh

    # Set the wait-for-postgres.sh script as the entrypoint to wait for the database before starting the application
    ENTRYPOINT ["sh", "/var/www/html/wait-for-db.sh"]

    CMD [ "php", "artisan", "serve", "--host=0.0.0.0", "--port=8000 & cd resources/js && npm run start" ]