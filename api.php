<?php
// ══════════════════════════════════════════════
//  🔌 VAULT — API
// ══════════════════════════════════════════════
session_start([
    'cookie_lifetime' => 0,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
]);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

require_once 'config.php';

// ── Helpers ────────────────────────────────────

function respond($data, int $code = 200): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $dsn = "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4";
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}

function requireAuth(): int {
    if (empty($_SESSION['user_id'])) respond(['error' => 'Unauthorized'], 401);
    if (!empty($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
        session_destroy();
        respond(['error' => 'Session expired'], 401);
    }
    $_SESSION['last_activity'] = time();
    return (int) $_SESSION['user_id'];
}

function encrypt(string $plain): string {
    $iv  = random_bytes(16);
    $enc = openssl_encrypt($plain, 'AES-256-CBC', ENC_KEY, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $enc);
}

function decrypt(string $encoded): string {
    $raw = base64_decode($encoded);
    $iv  = substr($raw, 0, 16);
    $enc = substr($raw, 16);
    return openssl_decrypt($enc, 'AES-256-CBC', ENC_KEY, OPENSSL_RAW_DATA, $iv) ?: '';
}

function input(): array {
    $body = file_get_contents('php://input');
    return json_decode($body, true) ?? [];
}

// ── Router ─────────────────────────────────────

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

try {
    match ($action) {
        'login'  => actionLogin(),
        'logout' => actionLogout(),
        'check'  => actionCheck(),
        'items'  => match ($method) {
            'GET'  => actionGetItems(),
            'POST' => actionCreateItem(),
            default => respond(['error' => 'Method not allowed'], 405),
        },
        'item'   => match ($method) {
            'GET'    => actionGetItem(),
            'PUT'    => actionUpdateItem(),
            'DELETE' => actionDeleteItem(),
            default  => respond(['error' => 'Method not allowed'], 405),
        },
        default => respond(['error' => 'Unknown action'], 404),
    };
} catch (PDOException $e) {
    respond(['error' => 'Database error: ' . $e->getMessage()], 500);
}

// ── Actions ────────────────────────────────────

function actionLogin(): void {
    $data     = input();
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if (!$username || !$password) respond(['error' => 'Введите логин и пароль'], 400);

    $stmt = db()->prepare("SELECT `id`, `password` FROM `users` WHERE `username` = ? LIMIT 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password'])) {
        respond(['error' => 'Неверный логин или пароль'], 401);
    }

    session_regenerate_id(true);
    $_SESSION['user_id']       = $user['id'];
    $_SESSION['last_activity'] = time();

    respond(['ok' => true, 'username' => $username]);
}

function actionLogout(): void {
    session_destroy();
    respond(['ok' => true]);
}

function actionCheck(): void {
    if (empty($_SESSION['user_id'])) respond(['authenticated' => false]);
    if (!empty($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
        session_destroy();
        respond(['authenticated' => false]);
    }
    $_SESSION['last_activity'] = time();
    respond(['authenticated' => true]);
}

function actionGetItems(): void {
    $uid  = requireAuth();
    $stmt = db()->prepare("SELECT `id`, `type`, `title`, `color`, `created_at`, `updated_at`, `data` FROM `vault_items` WHERE `user_id` = ? ORDER BY `sort_order` ASC, `created_at` DESC");
    $stmt->execute([$uid]);
    $items = $stmt->fetchAll();

    foreach ($items as &$item) {
        if ($item['type'] === 'card') {
            $raw = json_decode(decrypt($item['data']), true) ?: [];
            $num = preg_replace('/\D/', '', $raw['card_number'] ?? '');
            $item['preview'] = [
                'bank'   => $raw['bank']   ?? '',
                'expiry' => $raw['expiry'] ?? '',
                'last4'  => strlen($num) >= 4 ? substr($num, 0, 4) . ' •••• •••• ' . substr($num, -4) : '',
            ];
        }
        unset($item['data']); // never expose raw encrypted blob in list
    }
    unset($item);

    respond(['items' => $items]);
}

function actionGetItem(): void {
    $uid = requireAuth();
    $id  = (int) ($_GET['id'] ?? 0);

    $stmt = db()->prepare("SELECT * FROM `vault_items` WHERE `id` = ? AND `user_id` = ?");
    $stmt->execute([$id, $uid]);
    $item = $stmt->fetch();

    if (!$item) respond(['error' => 'Not found'], 404);

    $item['data'] = json_decode(decrypt($item['data']), true);
    respond(['item' => $item]);
}

function actionCreateItem(): void {
    $uid  = requireAuth();
    $data = input();

    $title = trim($data['title'] ?? '');
    $type  = $data['type'] ?? 'note';
    $color = $data['color'] ?? null;
    $payload = $data['data'] ?? [];

    if (!$title) respond(['error' => 'Название обязательно'], 400);
    if (!in_array($type, ['card','document','login','note'])) respond(['error' => 'Invalid type'], 400);

    $encrypted = encrypt(json_encode($payload));

    $stmt = db()->prepare("INSERT INTO `vault_items` (`user_id`, `type`, `title`, `data`, `color`) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$uid, $type, $title, $encrypted, $color]);

    respond(['ok' => true, 'id' => db()->lastInsertId()]);
}

function actionUpdateItem(): void {
    $uid = requireAuth();
    $id  = (int) ($_GET['id'] ?? 0);
    $data = input();

    $stmt = db()->prepare("SELECT `id` FROM `vault_items` WHERE `id` = ? AND `user_id` = ?");
    $stmt->execute([$id, $uid]);
    if (!$stmt->fetch()) respond(['error' => 'Not found'], 404);

    $title = trim($data['title'] ?? '');
    $type  = $data['type'] ?? 'note';
    $color = $data['color'] ?? null;
    $payload = $data['data'] ?? [];

    if (!$title) respond(['error' => 'Название обязательно'], 400);

    $encrypted = encrypt(json_encode($payload));

    $stmt = db()->prepare("UPDATE `vault_items` SET `type`=?, `title`=?, `data`=?, `color`=?, `updated_at`=NOW() WHERE `id`=? AND `user_id`=?");
    $stmt->execute([$type, $title, $encrypted, $color, $id, $uid]);

    respond(['ok' => true]);
}

function actionDeleteItem(): void {
    $uid = requireAuth();
    $id  = (int) ($_GET['id'] ?? 0);

    $stmt = db()->prepare("DELETE FROM `vault_items` WHERE `id` = ? AND `user_id` = ?");
    $stmt->execute([$id, $uid]);

    respond(['ok' => true]);
}
