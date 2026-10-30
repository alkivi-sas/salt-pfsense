<?php
// Keep stdout for JSON only: PHP notices/warnings go to stderr
ini_set("display_errors", "stderr");

require_once("config.inc");
require_once("pkg-utils.inc");

// Global debug flag - set to true to enable debug output
$DEBUG = false;

/**
 * Debug output function - prints to stdout when DEBUG is enabled
 */
function debug_log($message) {
    global $DEBUG;
    if ($DEBUG) {
        echo "[DEBUG] " . $message . "\n";
        flush(); // Ensure output is sent immediately
    }
}

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
            "name" => trim($repo["name"]),
            "description" => $repo["descr"],
            "default" => !empty($repo["default"])
        ];
    }

    echo json_encode($trains, JSON_PRETTY_PRINT);
}

/**
 * Wait for any `pfSense-upgrade -uf` processes to complete
 */
function wait_for_upgrade() {
    $max_wait_time = 300; // Maximum wait time in seconds
    $interval = 2;        // Check every 2 seconds (more frequent for quick processes)
    $elapsed_time = 0;
    $consecutive_empty_checks = 0;
    $required_empty_checks = 3; // Require 3 consecutive checks with no verified processes

    debug_log("wait_for_upgrade() started. Max wait time: {$max_wait_time}s, Check interval: {$interval}s");
    
    // Get our own PID to exclude it and our parent processes (do this once outside the loop)
    $our_pid = getmypid();
    $parent_pid = posix_getppid();
    $exclude_pids = [$our_pid, $parent_pid];
    debug_log("Excluding our own PIDs: " . implode(", ", $exclude_pids));
    
    // First check: see what processes are actually running (check multiple patterns, case-insensitive)
    // Exclude grep, sh -c, and our own script processes
    exec("ps aux | grep -iE '(pfSense-upgrade|rc.update_pkg_metadata|pfSense-repo-setup|lockf.*pfSense-upgrade)' | grep -vE '(grep|sh -c|php.*pkg_manager)'", $all_upgrade_procs, $proc_check);
    debug_log("All upgrade/repo-related processes: " . (empty($all_upgrade_procs) ? "NONE" : implode("\n", $all_upgrade_procs)));

    while ($elapsed_time < $max_wait_time) {
        // Collect all PIDs first, deduplicate, then verify them all at once
        $all_pids = [];
        $pid_to_type = []; // Track which type each PID belongs to
        
        // Check for pfSense-upgrade processes (case-insensitive)
        // Exclude grep, sh -c, and our own script processes
        exec("ps aux | grep -iE '(pfSense-upgrade|lockf.*pfSense-upgrade)' | grep -vE '(grep|sh -c|php.*pkg_manager)'", $upgrade_procs, $upgrade_ps_return);
        foreach ($upgrade_procs as $proc_line) {
            $parts = preg_split('/\s+/', trim($proc_line));
            if (count($parts) >= 2 && is_numeric($parts[1])) {
                $pid = (int)$parts[1];
                // Exclude our own PID and parent PID
                if ($pid > 0 && !in_array($pid, $exclude_pids)) {
                    $all_pids[$pid] = $pid;
                    $pid_to_type[$pid] = 'upgrade';
                }
            }
        }
        
        // Check for rc.update_pkg_metadata processes (case-insensitive)
        exec("ps aux | grep -iE 'rc.update_pkg_metadata' | grep -vE '(grep|sh -c|php.*pkg_manager)'", $metadata_procs, $metadata_ps_return);
        foreach ($metadata_procs as $proc_line) {
            $parts = preg_split('/\s+/', trim($proc_line));
            if (count($parts) >= 2 && is_numeric($parts[1])) {
                $pid = (int)$parts[1];
                if ($pid > 0 && !in_array($pid, $exclude_pids)) {
                    $all_pids[$pid] = $pid;
                    $pid_to_type[$pid] = 'metadata';
                }
            }
        }
        
        // Check for pfSense-repo-setup processes (case-insensitive)
        exec("ps aux | grep -iE 'pfSense-repo-setup' | grep -vE '(grep|sh -c|php.*pkg_manager)'", $repo_procs, $repo_ps_return);
        foreach ($repo_procs as $proc_line) {
            $parts = preg_split('/\s+/', trim($proc_line));
            if (count($parts) >= 2 && is_numeric($parts[1])) {
                $pid = (int)$parts[1];
                if ($pid > 0 && !in_array($pid, $exclude_pids)) {
                    $all_pids[$pid] = $pid;
                    $pid_to_type[$pid] = 'repo';
                }
            }
        }
        
        // Verify all PIDs exist in a single batch command (bulletproof verification)
        $valid_pids = [];
        $valid_upgrade_pids = [];
        $valid_metadata_pids = [];
        $valid_repo_pids = [];
        
        if (!empty($all_pids)) {
            $pid_list = implode(',', array_values($all_pids));
            exec("ps -p {$pid_list} -o pid --no-headers 2>/dev/null", $verified_output, $verify_return);
            
            foreach ($verified_output as $line) {
                $verified_pid = trim($line);
                if (is_numeric($verified_pid)) {
                    $verified_pid = (int)$verified_pid;
                    if ($verified_pid > 0 && isset($pid_to_type[$verified_pid])) {
                        $valid_pids[] = $verified_pid;
                        $type = $pid_to_type[$verified_pid];
                        if ($type == 'upgrade') {
                            $valid_upgrade_pids[] = $verified_pid;
                        } elseif ($type == 'metadata') {
                            $valid_metadata_pids[] = $verified_pid;
                        } elseif ($type == 'repo') {
                            $valid_repo_pids[] = $verified_pid;
                        }
                    }
                }
            }
        }
        
        // Also check for lock file existence as additional indicator
        $lock_file_exists = file_exists('/tmp/pfSense-upgrade.lock');
        
        debug_log("Check at {$elapsed_time}s:");
        debug_log("  - pfSense-upgrade: ps_lines=" . count($upgrade_procs) . ", unique_pids=" . count(array_filter($all_pids, function($pid) use ($pid_to_type) { return isset($pid_to_type[$pid]) && $pid_to_type[$pid] == 'upgrade'; })) . ", verified=" . count($valid_upgrade_pids) . (empty($valid_upgrade_pids) ? "" : " (" . implode(", ", $valid_upgrade_pids) . ")"));
        debug_log("  - rc.update_pkg_metadata: ps_lines=" . count($metadata_procs) . ", unique_pids=" . count(array_filter($all_pids, function($pid) use ($pid_to_type) { return isset($pid_to_type[$pid]) && $pid_to_type[$pid] == 'metadata'; })) . ", verified=" . count($valid_metadata_pids) . (empty($valid_metadata_pids) ? "" : " (" . implode(", ", $valid_metadata_pids) . ")"));
        debug_log("  - pfSense-repo-setup: ps_lines=" . count($repo_procs) . ", unique_pids=" . count(array_filter($all_pids, function($pid) use ($pid_to_type) { return isset($pid_to_type[$pid]) && $pid_to_type[$pid] == 'repo'; })) . ", verified=" . count($valid_repo_pids) . (empty($valid_repo_pids) ? "" : " (" . implode(", ", $valid_repo_pids) . ")"));
        debug_log("  - Lock file exists: " . ($lock_file_exists ? "YES" : "NO"));
        
        // Show only verified processes
        if (!empty($valid_upgrade_pids)) {
            $verified_lines = [];
            foreach ($upgrade_procs as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2 && in_array((int)$parts[1], $valid_upgrade_pids)) {
                    $verified_lines[] = $line;
                }
            }
            if (!empty($verified_lines)) {
                debug_log("  - Verified upgrade processes:\n" . implode("\n", array_unique($verified_lines)));
            }
        }
        if (!empty($valid_metadata_pids)) {
            $verified_lines = [];
            foreach ($metadata_procs as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2 && in_array((int)$parts[1], $valid_metadata_pids)) {
                    $verified_lines[] = $line;
                }
            }
            if (!empty($verified_lines)) {
                debug_log("  - Verified metadata processes:\n" . implode("\n", array_unique($verified_lines)));
            }
        }
        if (!empty($valid_repo_pids)) {
            $verified_lines = [];
            foreach ($repo_procs as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2 && in_array((int)$parts[1], $valid_repo_pids)) {
                    $verified_lines[] = $line;
                }
            }
            if (!empty($verified_lines)) {
                debug_log("  - Verified repo-setup processes:\n" . implode("\n", array_unique($verified_lines)));
            }
        }
        
        // Check if any verified processes are running OR lock file exists
        $total_valid = count($valid_pids);
        $has_active = ($total_valid > 0) || $lock_file_exists;
        
        if (!$has_active) {
            $consecutive_empty_checks++;
            debug_log("  - No verified processes or lock file (consecutive empty checks: {$consecutive_empty_checks}/{$required_empty_checks})");
            
            if ($consecutive_empty_checks >= $required_empty_checks) {
                debug_log("wait_for_upgrade() completed successfully after {$elapsed_time}s - no verified processes or lock file for {$required_empty_checks} consecutive checks");
                return true;
            }
        } else {
            $consecutive_empty_checks = 0;
            if ($lock_file_exists && $total_valid == 0) {
                debug_log("  - Lock file exists but no verified processes - waiting for lock to clear");
            }
        }

        // Wait and increment elapsed time
        debug_log("Waiting {$interval}s before next check... (elapsed: {$elapsed_time}s / {$max_wait_time}s)");
        sleep($interval);
        $elapsed_time += $interval;
    }

    debug_log("wait_for_upgrade() TIMED OUT after {$max_wait_time}s");
    // Final check - show what's still running (case-insensitive)
    exec("ps aux | grep -iE '(pfSense-upgrade|rc.update_pkg_metadata|pfSense-repo-setup)' | grep -vE '(grep|sh -c|php.*pkg_manager)'", $final_procs, $final_check);
    if (!empty($final_procs)) {
        debug_log("Processes still running at timeout:\n" . implode("\n", $final_procs));
    }
    return false; // Timed out waiting for the process to finish
}

/**
 * Read system/pkg_repo_conf_path (config_get_path() only exists on 2.7+)
 */
function get_repo_conf_path() {
    global $config;
    if (function_exists("config_get_path")) {
        return config_get_path("system/pkg_repo_conf_path", "");
    }
    return $config["system"]["pkg_repo_conf_path"] ?? "";
}

/**
 * Write system/pkg_repo_conf_path (config_set_path() only exists on 2.7+)
 */
function set_repo_conf_path($value) {
    global $config;
    if (function_exists("config_set_path")) {
        config_set_path("system/pkg_repo_conf_path", $value);
    } else {
        $config["system"]["pkg_repo_conf_path"] = $value;
    }
}

/**
 * Check whether $repo is the active train.
 *
 * CE ($n > 0): pkg_switch_repo() symlinks /usr/local/etc/pkg/repos/pfSense.conf to the repo .conf,
 * which is reliable even if the config was polluted by an older version of this helper.
 * 2.9 / Plus ($n == 0): the link is handled by pfSense-repo-setup, fall back to the config if not a link.
 *
 * @param int $n Number of parameters of pkg_switch_repo().
 */
function train_is_active($repo, $n) {
    global $g;
    $link = "/usr/local/etc/pkg/repos/{$g["product_name"]}.conf";
    if ($n > 0 || is_link($link)) {
        $target = is_link($link) ? readlink($link) : false;
        debug_log("train_is_active() - {$link} -> " . var_export($target, true));
        return $target === $repo["path"];
    }
    $conf = trim((string)get_repo_conf_path());
    $current = trim((string)pkg_get_repo_name($conf));
    debug_log("train_is_active() - no symlink, config: {$conf}, current repo: {$current}");
    return in_array(trim($repo["name"]), [$conf, $current], true);
}

/**
 * Activate a specific train by its name and update configuration
 *
 * pkg_switch_repo() and the expected pkg_repo_conf_path value depend on the version
 * (see system_update_settings.php):
 *   CE <= 2.6:      pkg_switch_repo($path), config = path
 *   CE 2.7 / 2.8:   pkg_switch_repo($repo_path, $repo_name), config = path
 *   2.9 / Plus:     pkg_switch_repo(), config = name
 *
 * @param string $fwbranch Firmware branch (e.g., "24_11").
 * @return bool True if the train is active at the end.
 */
function activate_train($fwbranch) {
    debug_log("activate_train() called with fwbranch: {$fwbranch}");

    $repos = pkg_list_repos();

    if (!$repos || !is_array($repos)) {
        echo json_encode([
            "success" => false,
            "message" => "No repositories found."
        ]);
        return false;
    }
    debug_log("activate_train() - Found " . count($repos) . " repositories");

    foreach ($repos as $repo) {
        debug_log("activate_train() - Checking repo: {$repo["name"]} (looking for: {$fwbranch})");
        if (trim($repo["name"]) !== trim($fwbranch)) {
            continue;
        }

        $n = (new ReflectionFunction("pkg_switch_repo"))->getNumberOfParameters();
        debug_log("activate_train() - pkg_switch_repo() takes {$n} parameter(s), path: {$repo["path"]}");

        if (train_is_active($repo, $n)) {
            echo json_encode([
                "success" => true,
                "message" => "Train {$fwbranch} is already active."
            ]);
            return true;
        }

        set_repo_conf_path($n == 0 ? $repo["name"] : $repo["path"]);
        write_config(gettext("Saved firmware branch setting."));

        if ($n == 0) {
            pkg_switch_repo();
        } elseif ($n == 1) {
            pkg_switch_repo($repo["path"]);
        } else {
            pkg_switch_repo(dirname($repo["path"]), $repo["name"]);
        }
        debug_log("activate_train() - pkg_switch_repo() completed");

        // Sleep 1 seconds for process to start
        sleep(1);

        // rc.update_pkg_metadata keeps running in background: a timeout is not a failure if the switch happened
        debug_log("activate_train() - Starting wait_for_upgrade()...");
        $finished = wait_for_upgrade();
        $active = train_is_active($repo, $n);

        if (!$active) {
            $message = "Train {$fwbranch} is not active after switching repository.";
        } elseif ($finished) {
            $message = "Train {$fwbranch} activated successfully.";
        } else {
            $message = "Train {$fwbranch} activated, metadata refresh still running.";
        }
        echo json_encode([
            "success" => $active,
            "message" => $message
        ]);

        return $active;
    }

    echo json_encode([
        "success" => false,
        "message" => "Firmware branch {$fwbranch} not found."
    ]);

    return false;
}

$options = getopt("", ["list", "activate:"]);

if (isset($options["list"])) {
    list_trains();
} elseif (isset($options["activate"])) {
    try {
        activate_train($options["activate"]);
    } catch (Throwable $e) {
        echo json_encode([
            "success" => false,
            "message" => $e->getMessage()
        ]);
    }
} else {
    echo json_encode([
        "usage" => [
            "--list" => "List available trains.",
            "--activate=<fwbranch>" => "Activate a train by its name (e.g., 24_11)."
        ]
    ]);
}
?>

