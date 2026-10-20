<?php
/*
 * Read or write a config.xml path that pfSense REST API does not model, on an allowlist.
 *
 * Usage: php config_path.php < request.json
 * request: {"op": "get"|"set"|"delete", "path": "system/sshguard_whitelist", "value": <json>,
 *           "apply": ["filter_configure", ...], "desc": "why"}
 * Output: {"value": <json>} for get, {"changed": bool} for set/delete.
 */
require_once("config.inc");
require_once("util.inc");

// Paths pfrest does not model, used by the Salt modules (docs/migration/coverage.md)
const ALLOWED = [
    '#^system/webgui/[a-z_]+$#',
    '#^system/sshguard_whitelist$#',
    '#^system/use_if_pppoe$#',
    '#^system/dns[1-9]gw$#',
    '#^installedpackages/(sudo|zabbixagentlts)/config/0/[a-z_]+$#',
    '#^syslog/numberofitems$#',
    '#^kea/custom_kea_config$#',
    '#^dhcpd/[a-z0-9]+/(custom_kea_config|numberoptions)$#',
];

// Actions run after a change, in the given order
const APPLY = [
    'filter_configure' => ['filter.inc', 'filter_configure'],
    'system_syslogd_start' => ['system.inc', 'system_syslogd_start'],
    'system_resolvconf_generate' => ['system.inc', 'system_resolvconf_generate'],
    'services_dhcpd_configure' => ['services.inc', 'services_dhcpd_configure'],
];

function fail($message) {
    fwrite(STDERR, $message . "\n");
    exit(1);
}

$request = json_decode(stream_get_contents(STDIN), true);
$op = $request['op'] ?? null;
$path = $request['path'] ?? '';
$allowed = false;
foreach (ALLOWED as $pattern) {
    if (preg_match($pattern, $path)) {
        $allowed = true;
    }
}
if (!$allowed) {
    fail("path $path is not allowed");
}
foreach ($request['apply'] ?? [] as $action) {
    if (!isset(APPLY[$action])) {
        fail("apply action $action is not allowed");
    }
}

$current = config_get_path($path);
if ($op === 'get') {
    echo json_encode(['value' => $current]);
    exit(0);
}

if ($op === 'set') {
    $changed = $current !== $request['value'];
    if ($changed) {
        config_set_path($path, $request['value']);
    }
} elseif ($op === 'delete') {
    $changed = $current !== null;
    if ($changed) {
        config_del_path($path);
    }
} else {
    fail("unknown op $op");
}

if ($changed) {
    write_config('salt-pfsense: ' . ($request['desc'] ?? $path));
    foreach ($request['apply'] ?? [] as $action) {
        [$include, $function] = APPLY[$action];
        require_once($include);
        $function();
    }
}
echo json_encode(['changed' => $changed]);
