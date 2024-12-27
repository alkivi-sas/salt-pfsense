<?php
require_once('pkg-utils.inc');

/**
 * List available trains (repositories)
 */
function list_trains() {
    $repos = pkg_list_repos();

    if (!$repos || !is_array($repos)) {
        echo json_encode(["error" => "No repositories found."]);
        return;
    }

    $trains = [];
    foreach ($repos as $repo) {
        $trains[] = [
            "id" => $repo['id'],
            "name" => $repo['name'],
            "description" => $repo['descr'],
            "default" => isset($repo['default']) ? (bool)$repo['default'] : false
        ];
    }

    echo json_encode($trains, JSON_PRETTY_PRINT);
}

/**
 * Wait for any `pfSense-upgrade -uf` processes to complete
 */
function wait_for_upgrade() {
    $max_wait_time = 300; // Maximum wait time in seconds
    $interval = 5;        // Check every 5 seconds
    $elapsed_time = 0;

    while ($elapsed_time < $max_wait_time) {
        // Check if the process is running
        exec("pgrep -f 'pfSense-upgrade -uf'", $output, $return_var);
        if (empty($output)) {
            // Process is no longer running
            return true;
        }

        // Wait and increment elapsed time
        sleep($interval);
        $elapsed_time += $interval;
    }

    return false; // Timed out waiting for the process to finish
}

/**
 * Activate a specific train by its name and update configuration
 * 
 * @param string $fwbranch Firmware branch (e.g., "24_11").
 * @return bool True if the train was activated, false if it was already active or timed out.
 */
function activate_train($fwbranch) {
    $repos = pkg_list_repos();

    if (!$repos || !is_array($repos)) {
        echo json_encode(["error" => "No repositories found."]);
        return false;
    }

    $current_repo_path = config_get_path('system/pkg_repo_conf_path');
    foreach ($repos as $repo) {
        if ($repo['name'] === $fwbranch) {
            // Check if the repository is already the default
            if ($current_repo_path === $repo['path']) {
                echo json_encode([
                    "success" => true,
                    "message" => "Train '{$fwbranch}' is already active."
                ]);
                return true; // No action needed
            }

            // Update configuration to set the desired firmware branch
            config_set_path('system/pkg_repo_conf_path', $repo['path']);
            write_config(gettext("Saved firmware branch setting."));
            pkg_switch_repo(g_get('pkg_repos_path'), $repo['name']);

            // Sleep 1 seconds for process to start
            sleep(1);

            // Wait for any background jobs to complete
            if (!wait_for_upgrade()) {
                echo json_encode([
                    "success" => false,
                    "message" => "Timed out waiting for background jobs to finish."
                ]);
                return false;
            }

            echo json_encode([
                "success" => true,
                "message" => "Train '{$fwbranch}' activated successfully."
            ]);

            return true;
        }
    }

    echo json_encode([
        "success" => false,
        "message" => "Firmware branch '{$fwbranch}' not found."
    ]);

    return false;
}

$options = getopt("", ["list", "activate:"]);

if (isset($options['list'])) {
    list_trains();
} elseif (isset($options['activate'])) {
    activate_train($options['activate']);
} else {
    echo json_encode([
        "usage" => [
            "--list" => "List available trains.",
            "--activate=<fwbranch>" => "Activate a train by its name (e.g., 24_11)."
        ]
    ]);
}
?>

