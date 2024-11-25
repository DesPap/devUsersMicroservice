<?php

return [
    'base_url' => env('KEYCLOAK_BASE_URL'),

    'external_base_url' => env('KEYCLOAK_EXTERNAL_BASE_URL'),

    'realm' => env('KEYCLOAK_REALM'),

    'client_id' => env('KEYCLOAK_CLIENT_ID'),

    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),

    'redirect_uri' => env('KEYCLOAK_REDIRECT_URI'),

    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY'),

    'token_encryption_algorithm' => env('KEYCLOAK_TOKEN_ENCRYPTION_ALGORITHM'),

    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE'),

    'user_provider_custom_retrieve_method' => null,

    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL'),

    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE'),

    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN'),

    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES'),

    'ignore_resources_validation' => env('KEYCLOAK_IGNORE_RESOURCES_VALIDATION'),

    'leeway' => env('KEYCLOAK_LEEWAY'),

    'input_key' => env('KEYCLOAK_TOKEN_INPUT_KEY')
];