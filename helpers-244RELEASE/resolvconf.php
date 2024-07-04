<?php
/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */
if (empty($argc)) {
    echo "Only accessible from the CLI.\r\n";
    die(1);
}

require_once("functions.inc");
require_once("filter.inc");
require_once("system.inc");



$retval = 0;
$retval |= system_resolvconf_generate();
exit($retval);

?>
