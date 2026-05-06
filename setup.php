<?php
// ══════════════════════════════════════════════════════════════
//  🔧 VAULT — Setup (защищён токеном, можно использовать повторно)
// ══════════════════════════════════════════════════════════════
session_start();
require_once 'config.php';

$error   = '';
$success = false;
$tokenOk = false;

// Шаг 1: проверка токена
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['token_check'])) {
    if (trim($_POST['setup_token'] ?? '') === SETUP_TOKEN) {
        $_SESSION['setup_ok'] = true;
    } else {
        $error = 'Неверный токен.';
    }
}
if (!empty($_SESSION['setup_ok'])) $tokenOk = true;

// Шаг 2: создание пользователя
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenOk && isset($_POST['username'])) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm'] ?? '';

    if (strlen($username) < 3)       $error = 'Логин минимум 3 символа.';
    elseif (strlen($password) < 8)   $error = 'Пароль минимум 8 символов.';
    elseif ($password !== $confirm)  $error = 'Пароли не совпадают.';
    else {
        try {
            $dsn = "mysql:host=".DB_HOST.";charset=utf8mb4";
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `".DB_NAME."` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE `".DB_NAME."`");

            $pdo->exec("CREATE TABLE IF NOT EXISTS `users` (
                `id`         INT AUTO_INCREMENT PRIMARY KEY,
                `username`   VARCHAR(100) NOT NULL UNIQUE,
                `password`   VARCHAR(255) NOT NULL,
                `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $pdo->exec("CREATE TABLE IF NOT EXISTS `vault_items` (
                `id`         INT AUTO_INCREMENT PRIMARY KEY,
                `user_id`    INT NOT NULL,
                `type`       ENUM('card','document','login','note') NOT NULL DEFAULT 'note',
                `title`      VARCHAR(255) NOT NULL,
                `data`       TEXT NOT NULL,
                `color`      VARCHAR(100) DEFAULT NULL,
                `sort_order` INT DEFAULT 0,
                `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $stmt = $pdo->prepare("SELECT COUNT(*) FROM `users` WHERE `username` = ?");
            $stmt->execute([$username]);
            if ($stmt->fetchColumn() > 0) {
                $error = 'Такой логин уже занят.';
            } else {
                $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                $stmt = $pdo->prepare("INSERT INTO `users` (`username`, `password`) VALUES (?, ?)");
                $stmt->execute([$username, $hash]);
                $_SESSION['setup_ok'] = false;
                $success = true;
            }
        } catch (PDOException $e) {
            $error = 'Ошибка БД: ' . $e->getMessage();
        }
    }
}
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vault — Setup</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Figtree', sans-serif; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    background: #0b0b18; position: relative; overflow: hidden;
  }
  body::before { content:''; position:fixed; width:600px; height:600px;
    background:radial-gradient(circle,rgba(99,102,241,.3),transparent 70%);
    top:-200px; right:-200px; pointer-events:none; }
  body::after  { content:''; position:fixed; width:500px; height:500px;
    background:radial-gradient(circle,rgba(236,72,153,.2),transparent 70%);
    bottom:-150px; left:-150px; pointer-events:none; }
  .card {
    background:rgba(255,255,255,.07); backdrop-filter:blur(24px) saturate(180%);
    -webkit-backdrop-filter:blur(24px) saturate(180%);
    border-radius:28px; padding:48px; width:100%; max-width:420px;
    border:1px solid rgba(255,255,255,.12);
    box-shadow:0 24px 64px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.15);
    position:relative; z-index:1; animation:fadeUp .5s ease both;
  }
  @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
  h1 { color:#fff; font-size:26px; font-weight:700; margin-bottom:6px; }
  .subtitle { color:rgba(255,255,255,.4); font-size:14px; margin-bottom:36px; }
  label { display:block; color:rgba(255,255,255,.6); font-size:12px; font-weight:600;
    text-transform:uppercase; letter-spacing:.8px; margin-bottom:8px; margin-top:20px; }
  input {
    width:100%; background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12);
    border-radius:14px; padding:14px 18px; color:#fff;
    font-family:'Figtree',sans-serif; font-size:15px; outline:none;
    transition:border-color .2s, background .2s;
  }
  input:focus { border-color:rgba(99,102,241,.7); background:rgba(255,255,255,.09); }
  input::placeholder { color:rgba(255,255,255,.25); }
  .error   { background:rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.3); border-radius:12px; padding:12px 16px; color:#fca5a5; font-size:14px; margin-top:20px; }
  .success { background:rgba(34,197,94,.15); border:1px solid rgba(34,197,94,.3); border-radius:12px; padding:16px 18px; color:#86efac; font-size:14px; margin-top:20px; line-height:1.7; }
  .success strong { color:#fff; }
  .success a { color:#86efac; }
  button {
    width:100%; margin-top:28px; padding:16px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6); border:none;
    border-radius:16px; color:#fff; font-family:'Figtree',sans-serif;
    font-size:16px; font-weight:600; cursor:pointer;
    box-shadow:0 8px 24px rgba(99,102,241,.4);
    transition:transform .15s, box-shadow .15s;
  }
  button:hover { transform:translateY(-1px); box-shadow:0 12px 32px rgba(99,102,241,.5); }
  .badge { display:inline-block; padding:3px 10px; border-radius:100px;
    background:rgba(99,102,241,.2); border:1px solid rgba(99,102,241,.3);
    color:rgba(180,180,255,.8); font-size:11px; font-weight:600; letter-spacing:.5px; margin-bottom:4px; }
</style>
</head>
<body>
<div class="card">
  <span class="badge">SETUP</span>
  <h1>🔐 Vault</h1>

  <?php if ($success): ?>
    <p class="subtitle">Пользователь создан!</p>
    <div class="success">
      ✅ <strong>Готово!</strong><br><br>
      Аккаунт успешно добавлен.<br>
      Файл setup.php можно оставить — он защищён токеном.<br><br>
      <a href="index.html">→ Перейти в Vault</a>
    </div>

  <?php elseif (!$tokenOk): ?>
    <p class="subtitle">Введи секретный токен для доступа</p>
    <?php if ($error): ?><div class="error">⚠️ <?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST">
      <input type="hidden" name="token_check" value="1">
      <label>Токен (из config.php)</label>
      <input type="password" name="setup_token" placeholder="••••••••" autofocus>
      <button type="submit">Продолжить →</button>
    </form>

  <?php else: ?>
    <p class="subtitle">Создание нового пользователя</p>
    <?php if ($error): ?><div class="error">⚠️ <?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST">
      <label>Логин</label>
      <input type="text" name="username" placeholder="например: faik2" autocomplete="username" required>
      <label>Пароль</label>
      <input type="password" name="password" placeholder="минимум 8 символов" autocomplete="new-password" required>
      <label>Подтверждение пароля</label>
      <input type="password" name="confirm" placeholder="повтори пароль" required>
      <button type="submit">Создать аккаунт</button>
    </form>
  <?php endif; ?>
</div>
</body>
</html>
