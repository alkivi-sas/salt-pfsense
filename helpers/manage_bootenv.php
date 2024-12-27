<?php
require_once('system_be.inc');

function list_boot_environments_as_json() {
    $handle = libbe_init();
    if (!$handle) {
        echo json_encode([]);
        return;
    }

    $bootenvs = [];
    $result = [];

    if (be_get_bootenv_props_ex($handle, $bootenvs) === BE_ERR_SUCCESS) {
        be_sort_bootenv_props($bootenvs, 'creation', SORT_ASC);
        be_sort_bootenv_props($bootenvs, 'active', SORT_DESC);

        foreach ($bootenvs as $name => $props) {
            $result[] = [
                "name" => $name,
                "version" => $props['version'] ?? "N/A",
                "description" => $props['descr'] ?? "N/A",
                "created" => $props['creation_nice'] ?? "Unknown",
                "last_booted" => $props['lastbooted_nice'] ?? "Never",
                "status" => $props['active'] ? "Active" : "Inactive",
                "protected" => $props['protect'] ? true : false,
                "used" => $props['used_nice'] ?? "Unknown"
            ];
        }
    } else {
        $result = ["error" => "Failed to retrieve boot environment properties."];
    }

    libbe_close($handle);
    echo json_encode($result, JSON_PRETTY_PRINT);
}

function delete_boot_environment($be_name) {
    $handle = libbe_init();
    if (!$handle) {
        die(json_encode(["error" => "Failed to initialize libbe."]));
    }

    if (be_exists($handle, $be_name) === BE_ERR_SUCCESS) {
        $result = be_bootenv_do_delete($handle, $be_name);
        if (empty($result)) {
            echo json_encode(["success" => "Boot environment '{$be_name}' successfully deleted."]);
        } else {
            echo json_encode(["error" => "Failed to delete boot environment '{$be_name}'.", "details" => $result]);
        }
    } else {
        echo json_encode(["error" => "Boot environment '{$be_name}' does not exist."]);
    }

    libbe_close($handle);
}

$options = getopt("", ["list", "delete:"]);
if (isset($options['list'])) {
    list_boot_environments_as_json();
} elseif (isset($options['delete'])) {
    delete_boot_environment($options['delete']);
} else {
    echo json_encode([
        "usage" => [
            "list" => "php manage_bootenv.php --list",
            "delete" => "php manage_bootenv.php --delete=<boot_environment_name>"
        ]
    ]);
}
?>
