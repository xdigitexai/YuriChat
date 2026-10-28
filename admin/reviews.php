<?php
declare(strict_types=1);

/*
 * YuroChat review admin.
 * Password hash lives outside the web root in .admin-pass (0600).
 * Reviews are appended to reviews.json, which is never tracked by git.
 */

session_name('yurochat_admin');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'secure'   => true,
    'samesite' => 'Lax',
]);
session_start();

const SITE_ROOT    = __DIR__ . '/..';
const PASS_FILE    = SITE_ROOT . '/.admin-pass';
const REVIEWS_FILE = SITE_ROOT . '/reviews.json';
const PHOTO_DIR    = SITE_ROOT . '/images/members';
const PHOTO_URL    = 'images/members';
const MAX_UPLOAD   = 2 * 1024 * 1024;
const RATE_WINDOW  = 60;
const RATE_LIMIT   = 5;

const ALLOWED_MIME = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
];

function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_ok(?string $token): bool
{
    return is_string($token) && !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

function is_logged_in(): bool
{
    return !empty($_SESSION['auth']) && $_SESSION['auth'] === true;
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function rate_file(): string
{
    return sys_get_temp_dir() . '/yurochat-admin-' . hash('sha256', client_ip()) . '.json';
}

function rate_hits(): array
{
    $file = rate_file();
    if (!is_file($file)) {
        return [];
    }
    $raw = @file_get_contents($file);
    $hits = json_decode((string) $raw, true);
    if (!is_array($hits)) {
        return [];
    }
    $now = time();
    return array_values(array_filter($hits, static fn($t) => is_int($t) && $now - $t < RATE_WINDOW));
}

function rate_blocked(): bool
{
    return count(rate_hits()) >= RATE_LIMIT;
}

function rate_hit(): void
{
    $hits = rate_hits();
    $hits[] = time();
    @file_put_contents(rate_file(), json_encode($hits), LOCK_EX);
    @chmod(rate_file(), 0600);
}

function rate_reset(): void
{
    @unlink(rate_file());
}

function read_reviews(): array
{
    if (!is_file(REVIEWS_FILE)) {
        return [];
    }
    $raw = @file_get_contents(REVIEWS_FILE);
    if ($raw === false || trim($raw) === '') {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? array_values(array_filter($data, 'is_array')) : [];
}

function write_reviews(array $rows): bool
{
    $json = json_encode(array_values($rows), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return false;
    }
    $json .= "\n";
    if (!is_dir(dirname(REVIEWS_FILE))) {
        return false;
    }
    $tmp = REVIEWS_FILE . '.tmp-' . bin2hex(random_bytes(6));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
        return false;
    }
    @chmod($tmp, 0644);
    if (!@rename($tmp, REVIEWS_FILE)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

function slugify(string $name): string
{
    $slug = strtolower(trim($name));
    if (function_exists('iconv')) {
        $conv = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $slug);
        if (is_string($conv) && $conv !== '') {
            $slug = $conv;
        }
    }
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug) ?? '';
    $slug = trim($slug, '-');
    return $slug !== '' ? substr($slug, 0, 40) : 'member';
}

/**
 * Validates and re-encodes an uploaded photo. Returns the stored relative
 * path, or null when no file was sent. Throws RuntimeException on bad input.
 */
function store_photo(array $file): ?string
{
    if (!isset($file['error']) || $file['error'] === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Upload failed (error ' . (int) $file['error'] . ').');
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        throw new RuntimeException('Invalid upload.');
    }
    if (($file['size'] ?? 0) > MAX_UPLOAD) {
        throw new RuntimeException('Photo is larger than 2 MB.');
    }
    $info = @getimagesize($file['tmp_name']);
    if ($info === false || empty($info['mime'])) {
        throw new RuntimeException('That file is not a readable image.');
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = (string) $finfo->file($file['tmp_name']);
    if (!isset(ALLOWED_MIME[$mime]) || !isset(ALLOWED_MIME[$info['mime']])) {
        throw new RuntimeException('Only JPEG, PNG or WebP images are accepted.');
    }
    $image = @imagecreatefromstring((string) file_get_contents($file['tmp_name']));
    if ($image === false) {
        throw new RuntimeException('That image could not be processed.');
    }
    $width  = imagesx($image);
    $height = imagesy($image);
    $scale  = min(1, 400 / max($width, $height));
    $newW   = max(1, (int) round($width * $scale));
    $newH   = max(1, (int) round($height * $scale));
    $canvas = imagecreatetruecolor($newW, $newH);
    imagefill($canvas, 0, 0, imagecolorallocate($canvas, 255, 255, 255));
    imagecopyresampled($canvas, $image, 0, 0, 0, 0, $newW, $newH, $width, $height);

    if (!is_dir(PHOTO_DIR) && !@mkdir(PHOTO_DIR, 0755, true) && !is_dir(PHOTO_DIR)) {
        throw new RuntimeException('Photo directory is not writable.');
    }
    $name = slugify((string) ($_POST['name'] ?? 'member')) . '-' . bin2hex(random_bytes(6)) . '.jpg';
    $path = PHOTO_DIR . '/' . $name;
    if (!@imagejpeg($canvas, $path, 85)) {
        throw new RuntimeException('Could not save the processed photo.');
    }
    imagedestroy($canvas);
    imagedestroy($image);
    @chmod($path, 0644);

    return PHOTO_URL . '/' . $name;
}

$errors   = [];
$notice   = '';
$saved    = false;
$loggedIn = is_logged_in();
$action   = $_POST['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok($_POST['csrf'] ?? null)) {
        $errors[] = 'Security token expired. Reload the page and try again.';
    } elseif ($action === 'login') {
        if (rate_blocked()) {
            $errors[] = 'Too many attempts. Wait a minute and try again.';
        } else {
            $hash = is_file(PASS_FILE) ? trim((string) file_get_contents(PASS_FILE)) : '';
            $pass = (string) ($_POST['password'] ?? '');
            if ($hash === '' || !password_verify($pass, $hash)) {
                rate_hit();
                $left = max(0, RATE_LIMIT - count(rate_hits()));
                $errors[] = 'Wrong password. ' . $left . ' attempt(s) left this minute.';
            } else {
                rate_reset();
                session_regenerate_id(true);
                $_SESSION['auth'] = true;
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                $loggedIn = true;
                $notice  = 'Signed in.';
            }
        }
    } elseif ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: reviews.php', true, 303);
        exit;
    } elseif (!$loggedIn) {
        $errors[] = 'Sign in first.';
    } elseif ($action === 'add') {
        $name    = trim((string) ($_POST['name'] ?? ''));
        $country = trim((string) ($_POST['country'] ?? ''));
        $amount  = trim((string) ($_POST['amount'] ?? ''));
        $method  = trim((string) ($_POST['method'] ?? ''));
        $date    = trim((string) ($_POST['date'] ?? ''));
        $quote   = trim((string) ($_POST['quote'] ?? ''));

        if ($name === '' || mb_strlen($name) > 100) {
            $errors[] = 'Name is required (max 100 characters).';
        }
        if ($country === '' || mb_strlen($country) > 60) {
            $errors[] = 'Country is required (max 60 characters).';
        }
        if ($amount === '' || mb_strlen($amount) > 40) {
            $errors[] = 'Amount is required (max 40 characters).';
        }
        if (mb_strlen($method) > 40 || mb_strlen($date) > 40 || mb_strlen($quote) > 600) {
            $errors[] = 'One of the optional fields is too long.';
        }

        $photo = null;
        if (!$errors) {
            try {
                $photo = store_photo($_FILES['photo'] ?? []);
            } catch (Throwable $t) {
                $errors[] = $t->getMessage();
            }
        }
        if (!$errors) {
            $rows   = read_reviews();
            $rows[] = [
                'name'    => $name,
                'country' => $country,
                'amount'  => $amount,
                'method'  => $method,
                'date'    => $date,
                'quote'   => $quote,
                'photo'   => $photo,
                'created' => date('c'),
            ];
            if (write_reviews($rows)) {
                $saved  = true;
                $notice = 'Saved. ' . count($rows) . ' review(s) on record.';
            } else {
                $errors[] = 'Could not write reviews.json — check file permissions.';
            }
        }
    } elseif ($action === 'delete') {
        $index = (int) ($_POST['index'] ?? -1);
        $rows  = read_reviews();
        if (isset($rows[$index])) {
            $photo = $rows[$index]['photo'] ?? null;
            if (is_string($photo) && str_starts_with($photo, PHOTO_URL . '/')) {
                $path = SITE_ROOT . '/' . $photo;
                if (is_file($path)) {
                    @unlink($path);
                }
            }
            array_splice($rows, $index, 1);
            if (write_reviews($rows)) {
                $notice = 'Entry deleted.';
            } else {
                $errors[] = 'Could not update reviews.json.';
            }
        } else {
            $errors[] = 'That entry no longer exists.';
        }
    }
}

$reviews    = read_reviews();
$lastFive   = array_reverse(array_slice($reviews, -5));
$configured = is_file(PASS_FILE) && trim((string) file_get_contents(PASS_FILE)) !== '';
$token      = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>YuroChat · Review admin</title>
<style>
:root{--purple:#4a1069;--purple-2:#75219c;--gold:#f6c755;--mint:#dff5e6;--green:#1f7a44;--ink:#12161c}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(900px 500px at 80% -10%,#3a0d54,#140a1e 60%);color:#eee6f4;font:15px/1.55 "Segoe UI",system-ui,sans-serif}
a{color:var(--gold)}
.top{background:linear-gradient(118deg,#2a0a3d,#46106a 50%,#67188f);padding:18px 0;border-bottom:1px solid #ffffff1f}
.wrap{width:min(880px,calc(100% - 40px));margin:auto}
.brand{display:flex;align-items:center;gap:11px;font-weight:800;font-size:19px;letter-spacing:-.03em}
.brand .mark{width:38px;height:38px;border-radius:12px;background:linear-gradient(180deg,#ffe08a,#f0b93f);display:grid;place-items:center;color:#4a1069;font-size:18px}
.brand .gold{color:var(--gold)}
.brand small{display:block;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#d9c4ec;font-weight:700;margin-top:2px}
.card{background:#1d1029;border:1px solid #3b2350;border-radius:20px;padding:24px;margin:26px 0;box-shadow:0 20px 50px #00000055}
h1{font-size:22px;margin:26px 0 4px}
h2{font-size:15px;letter-spacing:.06em;text-transform:uppercase;color:#bda6d4;margin:0 0 16px}
p.sub{color:#b9a7c9;margin:0 0 10px;font-size:14px}
label{display:block;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#c3aed6;margin:0 0 6px}
input,textarea{width:100%;background:#150c1f;border:1px solid #3d2554;border-radius:11px;padding:11px 13px;color:#f2ecf7;font:inherit;outline:none}
input:focus,textarea:focus{border-color:#a06bd0;box-shadow:0 0 0 3px #75219c44}
textarea{min-height:88px;resize:vertical}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.grid .full{grid-column:1/-1}
.btn{display:inline-flex;align-items:center;gap:9px;border:0;border-radius:999px;padding:12px 22px;font-weight:800;font-size:14px;cursor:pointer}
.btn-primary{background:linear-gradient(180deg,#ffe08a,#f0b93f);color:#3d1f02}
.btn-primary:hover{filter:brightness(1.05)}
.btn-ghost{background:#ffffff12;color:#e8dcf3;border:1px solid #ffffff26}
.btn-danger{background:#3a1220;color:#ffb4c4;border:1px solid #6b2237;padding:7px 14px;font-size:12px}
.note{border-radius:12px;padding:12px 14px;margin:0 0 16px;font-size:14px}
.ok{background:#18321f;border:1px solid #2c5c39;color:#bfe6c9}
.err{background:#37131b;border:1px solid #6d2434;color:#ffc9d3}
ul.errs{margin:0 0 16px;padding:14px 16px 14px 32px;list-style:disc}
.row{display:flex;gap:14px;align-items:center;border-top:1px solid #33203f;padding:12px 0}
.row:first-of-type{border-top:0}
.row img{width:46px;height:46px;border-radius:50%;object-fit:cover;background:#2a1a38}
.row .init{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;background:#efe7dc;color:#6a2b96;font-weight:800}
.row .who{flex:1;min-width:0}
.row .who strong{display:block;font-size:14px}
.row .who span{font-size:12px;color:#b6a4c6}
.row .amt{font-weight:800;color:#a8e6bb;white-space:nowrap}
form.inline{display:inline}
.hint{font-size:12px;color:#9d8bae;margin:6px 0 0}
</style>
</head>
<body>
<div class="top"><div class="wrap"><div class="brand"><span class="mark">y</span><span>Yuro<span class="gold">Chat</span><small>Review admin</small></span></div></div></div>
<div class="wrap">

<?php if (!$configured): ?>
  <div class="card">
    <h2>Not configured</h2>
    <p class="sub">Create <code>.admin-pass</code> in the site root with a password_hash() value, owned by www-data and chmod 600.</p>
  </div>
<?php elseif (!$loggedIn): ?>
  <div class="card" style="max-width:420px;margin-top:60px">
    <h2>Sign in</h2>
    <?php if ($errors): ?><div class="note err"><?= e($errors[0]) ?></div><?php endif; ?>
    <form method="post" action="reviews.php">
      <input type="hidden" name="csrf" value="<?= e($token) ?>">
      <input type="hidden" name="action" value="login">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <p class="hint">Five attempts per minute per IP.</p>
      <p><button class="btn btn-primary" type="submit">Sign in →</button></p>
    </form>
  </div>
<?php else: ?>
  <h1>Add a payout review</h1>
  <p class="sub">Saved to reviews.json and shown in the “Real Earners. Real Payouts.” section.</p>

  <?php if ($notice): ?><div class="note ok"><?= e($notice) ?></div><?php endif; ?>
  <?php if ($errors): ?><ul class="errs err"><?php foreach ($errors as $err): ?><li><?= e($err) ?></li><?php endforeach; ?></ul><?php endif; ?>

  <div class="card">
    <h2>New review</h2>
    <form method="post" action="reviews.php" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="<?= e($token) ?>">
      <input type="hidden" name="action" value="add">
      <div class="grid">
        <div><label for="name">Name</label><input id="name" name="name" maxlength="100" required></div>
        <div><label for="country">Country</label><input id="country" name="country" maxlength="60" required></div>
        <div><label for="amount">Amount</label><input id="amount" name="amount" maxlength="40" placeholder="KSh 2,500" required></div>
        <div><label for="method">Payment method</label><input id="method" name="method" maxlength="40" placeholder="M-Pesa"></div>
        <div><label for="date">Date</label><input id="date" name="date" maxlength="40" placeholder="2026-10-28"></div>
        <div><label for="photo">Photo (optional)</label><input id="photo" name="photo" type="file" accept="image/jpeg,image/png,image/webp"></div>
        <div class="full"><label for="quote">Quote (optional)</label><textarea id="quote" name="quote" maxlength="600"></textarea></div>
      </div>
      <p class="hint">JPEG, PNG or WebP up to 2 MB. Photos are re-encoded to max 400×400.</p>
      <p><button class="btn btn-primary" type="submit">Save review →</button></p>
    </form>
  </div>

  <div class="card">
    <h2>Last 5 entries · <?= count($reviews) ?> total</h2>
    <?php if (!$lastFive): ?><p class="sub">No entries yet.</p><?php endif; ?>
    <?php foreach ($lastFive as $i => $r):
        $realIndex = count($reviews) - 1 - $i;
        $initial = strtoupper(mb_substr(trim((string) ($r['name'] ?? '?')), 0, 1));
    ?>
      <div class="row">
        <?php if (!empty($r['photo']) && is_file(SITE_ROOT . '/' . $r['photo'])): ?>
          <img src="/<?= e($r['photo']) ?>" alt="">
        <?php else: ?>
          <span class="init"><?= e($initial) ?></span>
        <?php endif; ?>
        <div class="who">
          <strong><?= e((string) ($r['name'] ?? '')) ?> · <?= e((string) ($r['country'] ?? '')) ?></strong>
          <span><?= e((string) ($r['method'] ?? '')) ?><?= !empty($r['method']) && !empty($r['date']) ? ' · ' : '' ?><?= e((string) ($r['date'] ?? '')) ?> · <?= e(substr((string) ($r['created'] ?? ''), 0, 16)) ?></span>
        </div>
        <span class="amt"><?= e((string) ($r['amount'] ?? '')) ?></span>
        <form class="inline" method="post" action="reviews.php" onsubmit="return confirm('Delete this entry?')">
          <input type="hidden" name="csrf" value="<?= e($token) ?>">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="index" value="<?= (int) $realIndex ?>">
          <button class="btn btn-danger" type="submit">Delete</button>
        </form>
      </div>
    <?php endforeach; ?>
  </div>

  <form method="post" action="reviews.php" style="margin:0 0 40px">
    <input type="hidden" name="csrf" value="<?= e($token) ?>">
    <input type="hidden" name="action" value="logout">
    <button class="btn btn-ghost" type="submit">Sign out</button>
  </form>
<?php endif; ?>

</div>
</body>
</html>
