<?php
/*
 * Bootstrap the pfSense REST API (pfSense-pkg-RESTAPI) without any admin password:
 * dedicated group and user with least privileges, API key entry (hash only) and KeyAuth enabled.
 *
 * Usage: php restapi_bootstrap.php < request.json
 * request: {"username", "group", "privileges": [...], "key_hash", "hash_algo", "length_bytes", "descr"}
 * Output: {"changed": bool}. Never prints the key, its hash nor the user password.
 */
require_once("config.inc");
require_once("auth.inc");
require_once("pkg-utils.inc");

function fail($message) {
    fwrite(STDERR, $message . "\n");
    exit(1);
}

$request = json_decode(stream_get_contents(STDIN), true);
foreach (['username', 'group', 'privileges', 'key_hash', 'hash_algo', 'length_bytes', 'descr'] as $field) {
    if (!isset($request[$field])) {
        fail("missing field $field");
    }
}

$pkg_id = get_package_id('RESTAPI');
if ($pkg_id < 0) {
    fail('pfSense-pkg-RESTAPI is not installed');
}
global $config;
$before = json_encode($config);

// Group with the least privilege list
$groups = config_get_path('system/group', []);
$group_index = null;
foreach ($groups as $index => $group) {
    if ($group['name'] === $request['group']) {
        $group_index = $index;
    }
}
if ($group_index === null) {
    $gid = (int) config_get_path('system/nextgid');
    config_set_path('system/nextgid', $gid + 1);
    $groups[] = ['name' => $request['group'], 'description' => 'salt-pfsense REST API', 'scope' => 'local',
                 'gid' => $gid, 'member' => [], 'priv' => []];
    $group_index = count($groups) - 1;
}
$groups[$group_index]['priv'] = array_values($request['privileges']);

// Dedicated user, random password never stored nor printed
$users = config_get_path('system/user', []);
$user_index = null;
foreach ($users as $index => $user) {
    if ($user['name'] === $request['username']) {
        $user_index = $index;
    }
}
if ($user_index === null) {
    $uid = (int) config_get_path('system/nextuid');
    config_set_path('system/nextuid', $uid + 1);
    $user = ['name' => $request['username'], 'descr' => 'salt-pfsense REST API', 'scope' => 'user',
             'uid' => $uid, 'expires' => '', 'authorizedkeys' => '', 'ipsecpsk' => '', 'priv' => []];
    local_user_set_password($user, bin2hex(random_bytes(32)));
    $users[] = $user;
    $user_index = count($users) - 1;
}
$uid = $users[$user_index]['uid'];
$members = (array) ($groups[$group_index]['member'] ?? []);
if (!in_array($uid, $members)) {
    $members[] = $uid;
}
$groups[$group_index]['member'] = array_values($members);
config_set_path('system/group', $groups);
config_set_path('system/user', $users);

// API key entry (hash only) for the dedicated user
$conf_path = "installedpackages/package/$pkg_id/conf";
$keys = config_get_path("$conf_path/keys/key", []);
if (!is_array($keys)) {
    $keys = [];
}
$entry = ['username' => $request['username'], 'hash_algo' => $request['hash_algo'],
          'length_bytes' => (string) $request['length_bytes'], 'descr' => $request['descr'],
          'hash' => $request['key_hash']];
$key_index = null;
foreach ($keys as $index => $key) {
    if ($key['username'] === $request['username'] && $key['descr'] === $request['descr']) {
        $key_index = $index;
    }
}
if ($key_index === null) {
    $keys[] = $entry;
} else {
    $keys[$key_index] = $entry;
}
config_set_path("$conf_path/keys/key", $keys);

// KeyAuth must be an allowed authentication method (comma separated in config)
$methods = array_filter(explode(',', (string) config_get_path("$conf_path/auth_methods", 'BasicAuth')));
if (!in_array('KeyAuth', $methods)) {
    $methods[] = 'KeyAuth';
    config_set_path("$conf_path/auth_methods", implode(',', $methods));
}

$changed = json_encode($config) !== $before;
if ($changed) {
    write_config('salt-pfsense: REST API bootstrap');
    local_group_set(config_get_path("system/group/$group_index"));
    local_user_set(config_get_path("system/user/$user_index"));
}
echo json_encode(['changed' => $changed]);
