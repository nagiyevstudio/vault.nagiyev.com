<?php
// ══════════════════════════════════════════════
//  ⚙️  VAULT — Configuration
//  Заполни свои данные перед деплоем
// ══════════════════════════════════════════════

// Database
define('DB_HOST', 'localhost');
define('DB_NAME', 'alterace_vault');       // имя БД из cPanel
define('DB_USER', 'alterace_vault');       // пользователь БД
define('DB_PASS', 'ABZxl5n13!');       // пароль БД

// Encryption key — РОВНО 32 символа, измени на свой случайный!
// Можно сгенерировать: openssl rand -hex 16
define('ENC_KEY', 'yJ7xF2mxQVBm1N5DeZB46w1LAeVNThZr');

// Session timeout in seconds (3600 = 1 час)
define('SESSION_TIMEOUT', 7200);

// App title (показывается в браузере)
define('APP_TITLE', 'Vault');

define('SETUP_TOKEN', 'jaghrang-baghrang');