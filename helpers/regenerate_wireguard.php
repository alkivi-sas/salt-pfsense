<?php
require_once('wireguard/includes/wg.inc');
require_once('wireguard/includes/wg_guiconfig.inc');

wg_tunnel_sync(NULL, true, true);
?>
