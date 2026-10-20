<?php
function get_package_id($name) {
    foreach (config_get_path('installedpackages/package', []) as $id => $package) {
        if ($package['name'] === $name) {
            return $id;
        }
    }
    return -1;
}
