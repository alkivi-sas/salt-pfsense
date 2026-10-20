<?php
/*
 * Minimal stand-in for pfSense config.inc used to run the helpers in unit tests.
 * $config is loaded from the JSON file named by SALT_PFSENSE_TEST_CONFIG and written back by write_config().
 * Every call to an apply/system function is appended to SALT_PFSENSE_TEST_CALLS.
 */
global $config;
$config = json_decode(file_get_contents(getenv('SALT_PFSENSE_TEST_CONFIG')), true);

function _test_record($name, $args = []) {
    file_put_contents(getenv('SALT_PFSENSE_TEST_CALLS'), json_encode([$name, $args]) . "\n", FILE_APPEND);
}

function &_test_node(&$array, $path, $create) {
    $node = &$array;
    foreach (explode('/', $path) as $key) {
        if ($key === '') {
            continue;
        }
        if (!is_array($node) || !array_key_exists($key, $node)) {
            if (!$create) {
                $null = null;
                return $null;
            }
            if (!is_array($node)) {
                $node = [];
            }
            $node[$key] = null;
        }
        $node = &$node[$key];
    }
    return $node;
}

function config_get_path($path, $default = null) {
    global $config;
    $node = &_test_node($config, $path, false);
    return $node === null ? $default : $node;
}

function config_set_path($path, $value) {
    global $config;
    $node = &_test_node($config, $path, true);
    $node = $value;
}

function config_del_path($path) {
    global $config;
    $parts = explode('/', $path);
    $last = array_pop($parts);
    $parent = &_test_node($config, implode('/', $parts), false);
    if (is_array($parent)) {
        unset($parent[$last]);
    }
}

function write_config($desc) {
    global $config;
    file_put_contents(getenv('SALT_PFSENSE_TEST_CONFIG'), json_encode($config));
    _test_record('write_config', [$desc]);
}
