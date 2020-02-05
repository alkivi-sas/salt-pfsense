<?php
/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */
if (empty($argc)) {
    echo "Only accessible from the CLI.\r\n";
    die(1);
}

require_once("guiconfig.inc");
require_once("functions.inc");
require_once("filter.inc");
require_once("shaper.inc");


$retval = 0;
$retval |= filter_configure();
pfSense_handle_custom_code("/usr/local/pkg/firewall_nat/apply");
exit($retval);

?>
