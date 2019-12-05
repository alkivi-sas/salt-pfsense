<?php
/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */
if (empty($argc)) {
    echo "Only accessible from the CLI.\r\n";
    die(1);
}
if ($argc != 4) {
    echo "Usage: php " . $argv[0] . " common_name descr caref\r\n";
    die(1);
}

require_once("certs.inc");
require_once("openvpn.inc");
require_once("pfsense-utils.inc");
require_once("vpn.inc");

$dn_commonname = $argv[1];
$descr = $argv[2];
$caref = $argv[3];
$keylen = 2048;
$lifetime = 3650;
$type = 'user';
$digest_alg = 'sha256';

$ca =& lookup_ca($caref);

if (!$ca) {
    echo "Unable to find ca $caref.\r\n";
    die(1);
}

$cert = array();
$cert['refid'] = uniqid();
$cert['descr'] = $descr;
$dn = array('commonName' => $dn_commonname);
$dn['stateOrProvinceName'] = 'Nord';
$dn['countryName'] = 'FR';
$dn['localityName'] = 'Lille';
$dn['organizationName'] = 'Alkivi';


$cert_result = cert_create($cert, $caref, $keylen, $lifetime, $dn, $type, $digest_alg);
if (!$cert_result) {
    echo "Unable to create cert.";
    echo $cert_result;
    die(1);
}
vpn_ipsec_configure();
echo json_encode($cert);
exit;
