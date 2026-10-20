<?php
/*
 * Set user fields that pfSense REST API does not model, then sync the FreeBSD account.
 * The pillar holds bcrypt hashes (not clear passwords), which pfrest can not take.
 *
 * Usage: php user_set_fields.php < request.json
 * request: {"name": "<user>", "fields": {"bcrypt-hash": "...", "dashboardcolumns": "2", "webguicss": "pfSense.css"}}
 * Output: {"changed": bool}. Never prints the hash.
 */
require_once("config.inc");
require_once("auth.inc");

const ALLOWED = ['bcrypt-hash', 'dashboardcolumns', 'webguicss'];

function fail($message) {
    fwrite(STDERR, $message . "\n");
    exit(1);
}

$request = json_decode(stream_get_contents(STDIN), true);
if (!isset($request['name']) || !isset($request['fields']) || !is_array($request['fields'])) {
    fail('request needs name and fields');
}

$users = config_get_path('system/user', []);
$index = null;
foreach ($users as $i => $user) {
    if ($user['name'] === $request['name']) {
        $index = $i;
    }
}
if ($index === null) {
    fail('unknown user ' . $request['name']);
}

$changed = false;
foreach ($request['fields'] as $field => $value) {
    if (!in_array($field, ALLOWED, true)) {
        fail("field $field is not allowed");
    }
    if (($users[$index][$field] ?? null) !== $value) {
        $users[$index][$field] = $value;
        $changed = true;
    }
}

if ($changed) {
    config_set_path("system/user/$index", $users[$index]);
    write_config('salt-pfsense: user ' . $request['name'] . ' fields');
    local_user_set(config_get_path("system/user/$index"));
}
echo json_encode(['changed' => $changed]);
