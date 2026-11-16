<?php

/**
 * Normalize VPN-UI base URLs while preserving reverse-proxy mount paths.
 * Bare host:port/path values are treated as HTTPS URLs.
 */
if (!function_exists('vpn_ui_normalize_base_url')) {
    function vpn_ui_normalize_base_url(string $url): ?string
    {
        $url = trim($url);
        if ($url === '' || preg_match('/[\r\n\s]/', $url)) {
            return null;
        }

        if (strpos($url, '//') === 0) {
            $url = 'https:' . $url;
        } elseif (!preg_match('~^[a-z][a-z0-9+.-]*://~i', $url)) {
            // Accept common input such as vpn.example.com:8443/amc.
            $url = 'https://' . $url;
        }

        $parts = parse_url($url);
        if (!is_array($parts)
            || !in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || trim((string) ($parts['host'] ?? '')) === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return null;
        }

        if (isset($parts['port']) && ((int) $parts['port'] < 1 || (int) $parts['port'] > 65535)) {
            return null;
        }

        // Keep paths such as /amc intact: API requests are made below this prefix.
        return rtrim($url, '/');
    }
}

/** Minimal adapter for the FastAPI VPN Panel used by Faoxima. */
if (!function_exists('vpn_ui_http_request')) {
    function vpn_ui_http_request(string $baseUrl, string $method, string $path, ?array $payload = null, ?string $token = null): array
    {
        if (!function_exists('curl_init')) {
            return ['ok' => false, 'status' => 0, 'data' => null, 'msg' => 'PHP cURL extension is required'];
        }
        $baseUrl = vpn_ui_normalize_base_url($baseUrl);
        if ($baseUrl === null) {
            return ['ok' => false, 'status' => 0, 'data' => null, 'msg' => 'Invalid VPN Panel URL. Use https://host:port/amc or host:port/amc'];
        }
        $url = $baseUrl . '/' . ltrim($path, '/');
        $headers = ['Accept: application/json', 'Content-Type: application/json'];
        if ($token !== null && $token !== '') {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 25,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if ($payload !== null) {
            $encoded = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($encoded === false) {
                curl_close($ch);
                return ['ok' => false, 'status' => 0, 'data' => null, 'msg' => 'Could not encode request JSON'];
            }
            curl_setopt($ch, CURLOPT_POSTFIELDS, $encoded);
        }
        $body = curl_exec($ch);
        $curlError = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false) {
            return ['ok' => false, 'status' => 0, 'data' => null, 'msg' => $curlError !== '' ? $curlError : 'Connection to VPN Panel failed'];
        }
        $data = json_decode((string) $body, true);
        if ($status < 200 || $status >= 300) {
            $message = is_array($data) ? ($data['detail'] ?? ($data['message'] ?? ($data['msg'] ?? ''))) : '';
            if (is_array($message)) {
                // FastAPI/Pydantic errors may include the rejected `input` value.
                // Never forward that field because it can contain a password.
                $safeErrors = [];
                foreach ($message as $error) {
                    if (!is_array($error)) {
                        continue;
                    }
                    $location = isset($error['loc']) && is_array($error['loc'])
                        ? implode('.', array_map('strval', $error['loc']))
                        : '';
                    $detail = trim((string) ($error['msg'] ?? ''));
                    if ($detail !== '') {
                        $safeErrors[] = ($location !== '' ? $location . ': ' : '') . $detail;
                    }
                }
                $message = implode(' | ', $safeErrors);
            }
            if (!is_scalar($message) || trim((string) $message) === '') {
                $message = 'VPN Panel returned HTTP ' . $status;
            }
            return ['ok' => false, 'status' => $status, 'data' => null, 'msg' => substr((string) $message, 0, 500)];
        }
        if ($body !== '' && !is_array($data)) {
            return ['ok' => false, 'status' => $status, 'data' => null, 'msg' => 'VPN Panel returned invalid JSON'];
        }
        return ['ok' => true, 'status' => $status, 'data' => is_array($data) ? $data : [], 'msg' => ''];
    }
}

if (!function_exists('vpn_ui_jwt_exp')) {
    function vpn_ui_jwt_exp(string $token): ?int
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[1] === '') {
            return null;
        }
        $payloadPart = strtr($parts[1], '-_', '+/');
        $payloadPart .= str_repeat('=', (4 - strlen($payloadPart) % 4) % 4);
        $decoded = base64_decode($payloadPart, true);
        if ($decoded === false) {
            return null;
        }
        $payload = json_decode($decoded, true);
        return is_array($payload) && is_numeric($payload['exp'] ?? null)
            ? (int) $payload['exp']
            : null;
    }
}

if (!function_exists('vpn_ui_db')) {
    function vpn_ui_db(): ?PDO
    {
        global $pdo;
        if ($pdo instanceof PDO) {
            return $pdo;
        }
        if (function_exists('getDatabaseConnection')) {
            $connection = getDatabaseConnection();
            return $connection instanceof PDO ? $connection : null;
        }
        return null;
    }
}

if (!function_exists('vpn_ui_panel_fingerprint')) {
    function vpn_ui_panel_fingerprint(string $baseUrl, string $username): string
    {
        return hash('sha256', rtrim(trim($baseUrl), '/') . "\0" . trim($username));
    }
}

if (!function_exists('vpn_ui_read_stored_token')) {
    function vpn_ui_read_stored_token(array $panel, string $fingerprint): ?string
    {
        $raw = $panel['datelogin'] ?? null;
        $codePanel = trim((string) ($panel['code_panel'] ?? ''));
        $db = vpn_ui_db();
        if ($db instanceof PDO && $codePanel !== '') {
            try {
                $stmt = $db->prepare('SELECT datelogin FROM marzban_panel WHERE code_panel = ? LIMIT 1');
                $stmt->execute([$codePanel]);
                $fresh = $stmt->fetchColumn();
                if (is_string($fresh)) {
                    $raw = $fresh;
                }
            } catch (Throwable $e) {
                error_log('vpn_ui_read_stored_token: ' . $e->getMessage());
            }
        }
        $stored = is_array($raw) ? $raw : (is_string($raw) ? json_decode($raw, true) : null);
        if (!is_array($stored)
            || !isset($stored['vpn_ui_token'])
            || !is_string($stored['vpn_ui_token'])
            || ($stored['panel_fingerprint'] ?? '') !== $fingerprint) {
            return null;
        }
        $expiresAt = vpn_ui_jwt_exp($stored['vpn_ui_token']);
        if ($expiresAt === null || $expiresAt <= time() + 60) {
            return null;
        }
        return $stored['vpn_ui_token'];
    }
}

if (!function_exists('vpn_ui_store_token')) {
    function vpn_ui_store_token(array $panel, string $fingerprint, string $token): void
    {
        $codePanel = trim((string) ($panel['code_panel'] ?? ''));
        if ($codePanel === '') {
            return;
        }
        $serialized = json_encode([
            'vpn_ui_token' => $token,
            'panel_fingerprint' => $fingerprint,
            'stored_at' => time(),
        ], JSON_UNESCAPED_SLASHES);
        if (!is_string($serialized)) {
            return;
        }
        $db = vpn_ui_db();
        if ($db instanceof PDO) {
            try {
                $stmt = $db->prepare('UPDATE marzban_panel SET datelogin = ? WHERE code_panel = ?');
                $stmt->execute([$serialized, $codePanel]);
                return;
            } catch (Throwable $e) {
                error_log('vpn_ui_store_token: ' . $e->getMessage());
            }
        }
        if (function_exists('update')) {
            try {
                update('marzban_panel', 'datelogin', $serialized, 'code_panel', $codePanel);
            } catch (Throwable $e) {
                error_log('vpn_ui_store_token fallback: ' . $e->getMessage());
            }
        }
    }
}

if (!function_exists('vpn_ui_login')) {
    function vpn_ui_login(array $panel, bool $force = false): array
    {
        static $tokenCache = [];
        $baseUrl = vpn_ui_normalize_base_url((string) ($panel['url_panel'] ?? ''));
        if ($baseUrl === null) {
            return ['ok' => false, 'token' => null, 'msg' => 'Invalid VPN Panel URL. Use https://host:port/amc or host:port/amc'];
        }
        $username = trim((string) ($panel['username_panel'] ?? ''));
        $password = (string) ($panel['password_panel'] ?? '');
        $cacheKey = hash('sha256', $baseUrl . "\0" . $username . "\0" . $password);
        $fingerprint = vpn_ui_panel_fingerprint($baseUrl, $username);
        if (!$force && !empty($tokenCache[$cacheKey])) {
            $expiresAt = vpn_ui_jwt_exp($tokenCache[$cacheKey]);
            if ($expiresAt !== null && $expiresAt > time() + 60) {
                return ['ok' => true, 'token' => $tokenCache[$cacheKey], 'msg' => ''];
            }
            unset($tokenCache[$cacheKey]);
        }
        if (!$force) {
            $storedToken = vpn_ui_read_stored_token($panel, $fingerprint);
            if ($storedToken !== null) {
                $tokenCache[$cacheKey] = $storedToken;
                return ['ok' => true, 'token' => $storedToken, 'msg' => ''];
            }
        }
        if ($username === '' || $password === '') {
            return ['ok' => false, 'token' => null, 'msg' => 'VPN Panel URL, Super Admin username and password are required'];
        }
        $response = vpn_ui_http_request($baseUrl, 'POST', '/api/auth/login', [
            'username' => $username,
            'password' => $password,
        ]);
        if (empty($response['ok'])) {
            return ['ok' => false, 'token' => null, 'msg' => $response['msg'] ?? 'VPN Panel login failed', 'status' => $response['status'] ?? 0];
        }
        $data = $response['data'];
        if (strtolower((string) ($data['role'] ?? '')) !== 'superadmin') {
            return ['ok' => false, 'token' => null, 'msg' => 'VPN Panel account must have the superadmin role'];
        }
        if (!empty($data['internal_license_required'])) {
            return ['ok' => false, 'token' => null, 'msg' => 'VPN Panel internal license is expired or locked'];
        }
        $token = trim((string) ($data['access_token'] ?? ''));
        if ($token === '') {
            return ['ok' => false, 'token' => null, 'msg' => 'VPN Panel login did not return an access token'];
        }
        $tokenCache[$cacheKey] = $token;
        vpn_ui_store_token($panel, $fingerprint, $token);
        return ['ok' => true, 'token' => $token, 'msg' => ''];
    }
}

if (!function_exists('vpn_ui_api_request')) {
    function vpn_ui_api_request(array $panel, string $method, string $path, ?array $payload = null, bool $retryAuth = true): array
    {
        $login = vpn_ui_login($panel);
        if (empty($login['ok'])) {
            return $login;
        }
        $response = vpn_ui_http_request((string) ($panel['url_panel'] ?? ''), $method, $path, $payload, $login['token']);
        if (($response['status'] ?? 0) === 401 && $retryAuth) {
            $login = vpn_ui_login($panel, true);
            if (empty($login['ok'])) {
                return $login;
            }
            $response = vpn_ui_http_request((string) ($panel['url_panel'] ?? ''), $method, $path, $payload, $login['token']);
        }
        return $response;
    }
}

if (!function_exists('vpn_ui_test_connection')) {
    function vpn_ui_test_connection(string $url, string $username, string $password): array
    {
        $normalizedUrl = vpn_ui_normalize_base_url($url);
        if ($normalizedUrl === null) {
            return ['status' => false, 'msg' => 'Invalid VPN Panel URL. Use https://host:port/amc or host:port/amc'];
        }
        $panel = ['url_panel' => $normalizedUrl, 'username_panel' => trim($username), 'password_panel' => $password];
        $login = vpn_ui_login($panel, true);
        return ['status' => !empty($login['ok']), 'msg' => $login['msg'] ?? ''];
    }
}

if (!function_exists('vpn_ui_enabled_protocols')) {
    /** Return only protocols that the VPN Panel reports as installed and healthy. */
    function vpn_ui_enabled_protocols(array $panel): array
    {
        $response = vpn_ui_api_request($panel, 'GET', '/api/settings/protocol-center?fresh=1');
        if (empty($response['ok'])) {
            return ['status' => false, 'protocols' => [], 'msg' => $response['msg'] ?? 'Could not read VPN Panel protocol status'];
        }
        $rows = $response['data']['protocols'] ?? null;
        if (!is_array($rows)) {
            return ['status' => false, 'protocols' => [], 'msg' => 'VPN Panel returned an invalid protocol status'];
        }
        $supported = ['l2tp', 'pptp', 'openvpn', 'sstp', 'ikev2', 'openconnect', 'vmess', 'vless'];
        $enabled = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $key = strtolower(trim((string) ($row['key'] ?? '')));
            if (in_array($key, $supported, true)
                && !empty($row['installed'])
                && strtolower((string) ($row['state'] ?? '')) === 'active') {
                $enabled[] = $key;
            }
        }
        if (empty($enabled)) {
            return ['status' => false, 'protocols' => [], 'msg' => 'هیچ پروتکل نصب‌شده و سالمی در VPN Panel برای ساخت حساب فعال نیست.'];
        }
        return ['status' => true, 'protocols' => array_values(array_unique($enabled)), 'msg' => ''];
    }
}

if (!function_exists('vpn_ui_find_user')) {
    function vpn_ui_find_user(array $panel, string $username): array
    {
        $response = vpn_ui_api_request($panel, 'GET', '/api/users');
        if (empty($response['ok'])) {
            return ['status' => false, 'msg' => $response['msg'] ?? 'Could not list VPN Panel users'];
        }
        $users = $response['data'];
        if (isset($users['users']) && is_array($users['users'])) {
            $users = $users['users'];
        }
        if (!is_array($users)) {
            return ['status' => false, 'msg' => 'VPN Panel returned an invalid users list'];
        }
        foreach ($users as $user) {
            if (is_array($user) && (string) ($user['username'] ?? '') === $username) {
                return ['status' => true, 'data' => $user, 'msg' => ''];
            }
        }
        return ['status' => false, 'msg' => 'User not found'];
    }
}

if (!function_exists('vpn_ui_create_user')) {
    function vpn_ui_create_user(array $panel, array $payload): array
    {
        $response = vpn_ui_api_request($panel, 'POST', '/api/users', $payload);
        return ['status' => !empty($response['ok']), 'data' => $response['data'] ?? null, 'msg' => $response['msg'] ?? '', 'http_code' => $response['status'] ?? 0];
    }
}

if (!function_exists('vpn_ui_update_user')) {
    function vpn_ui_update_user(array $panel, string $username, array $payload): array
    {
        $found = vpn_ui_find_user($panel, $username);
        if (empty($found['status'])) {
            return ['status' => false, 'msg' => $found['msg'] ?? 'User not found'];
        }
        $userId = (int) ($found['data']['id'] ?? 0);
        if ($userId < 1) {
            return ['status' => false, 'msg' => 'VPN Panel user ID is missing'];
        }
        $allowed = ['password', 'enable_l2tp', 'enable_pptp', 'enable_openvpn', 'enable_sstp', 'enable_ikev2', 'enable_openconnect', 'enable_vmess', 'enable_vless', 'quota_gb', 'max_devices', 'speed_limit_mbps', 'download_limit_mbps', 'upload_limit_mbps', 'openvpn_auth_mode', 'sstp_auth_mode', 'expire_mode', 'expire_date', 'expire_after_days', 'is_active', 'note', 'server_targets'];
        $payload = array_intersect_key($payload, array_fill_keys($allowed, true));
        $response = vpn_ui_api_request($panel, 'PUT', '/api/users/' . $userId, $payload);
        return ['status' => !empty($response['ok']), 'data' => $response['data'] ?? null, 'msg' => $response['msg'] ?? '', 'http_code' => $response['status'] ?? 0];
    }
}

if (!function_exists('vpn_ui_delete_user')) {
    function vpn_ui_delete_user(array $panel, string $username): array
    {
        $found = vpn_ui_find_user($panel, $username);
        if (empty($found['status'])) {
            return ['status' => false, 'msg' => $found['msg'] ?? 'User not found'];
        }
        $userId = (int) ($found['data']['id'] ?? 0);
        if ($userId < 1) {
            return ['status' => false, 'msg' => 'VPN Panel user ID is missing'];
        }
        $response = vpn_ui_api_request($panel, 'DELETE', '/api/users/' . $userId);
        return ['status' => !empty($response['ok']), 'data' => $response['data'] ?? null, 'msg' => $response['msg'] ?? ''];
    }
}

if (!function_exists('vpn_ui_reset_user_usage')) {
    function vpn_ui_reset_user_usage(array $panel, string $username): array
    {
        $found = vpn_ui_find_user($panel, $username);
        if (empty($found['status'])) {
            return ['status' => false, 'msg' => $found['msg'] ?? 'User not found'];
        }
        $userId = (int) ($found['data']['id'] ?? 0);
        if ($userId < 1) {
            return ['status' => false, 'msg' => 'VPN Panel user ID is missing'];
        }
        $response = vpn_ui_api_request($panel, 'POST', '/api/users/' . $userId . '/reset-usage');
        return ['status' => !empty($response['ok']), 'data' => $response['data'] ?? null, 'msg' => $response['msg'] ?? ''];
    }
}

if (!function_exists('vpn_ui_capability_report')) {
    function vpn_ui_capability_report(array $panel, array &$report): void
    {
        $login = vpn_ui_login($panel, true);
        if (empty($login['ok'])) {
            rx_cap_set($report, 'connection', 'failed', (string) ($login['msg'] ?? 'Login failed'));
            rx_cap_mark_untested_after_connection_failure($report);
            return;
        }
        rx_cap_set($report, 'connection', 'verified', 'ورود Super Admin و لایسنس داخلی تأیید شد.');
        $users = vpn_ui_api_request($panel, 'GET', '/api/users');
        if (empty($users['ok'])) {
            rx_cap_set($report, 'list_users', 'failed', (string) ($users['msg'] ?? 'Users endpoint failed'));
            return;
        }
        rx_cap_set($report, 'list_users', 'verified', 'لیست کاربران از API خوانده شد.');
        rx_cap_set($report, 'read_user', 'allowed', 'خواندن حساب از لیست کاربران پشتیبانی می‌شود.');
        rx_cap_set($report, 'create', 'allowed', 'API ساخت کاربر در دسترس است؛ ساخت آزمایشی انجام نشد.');
        rx_cap_set($report, 'update', 'allowed', 'API ویرایش و تمدید کاربر در دسترس است.');
        rx_cap_set($report, 'delete', 'allowed', 'API حذف کاربر در دسترس است؛ حذف آزمایشی انجام نشد.');
        rx_cap_set($report, 'reset', 'allowed', 'API ریست مصرف در دسترس است.');
        rx_cap_set($report, 'configs', 'allowed', 'لینک اشتراک از API کاربر دریافت می‌شود.');
        rx_cap_set($report, 'revoke', 'unsupported', 'API فعلی VPN Panel عملیات بازسازی/لغو لینک اختصاصی ارائه نمی‌کند.');
        rx_cap_set($report, 'resources', 'unsupported', 'ساخت کاربر از پروتکل‌های فعال پنل استفاده می‌کند و نیاز به انتخاب دستی اینباند ندارد.');
    }
}
