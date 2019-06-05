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
    echo "Usage: php " . $argv[0] . " crlref certref reason\r\n";
    die(1);
}

require_once("certs.inc");
require_once("openvpn.inc");
require_once("pfsense-utils.inc");
require_once("vpn.inc");

$crlref = $argv[1];
$certref = $argv[2];
$reason = $argv[3];

$crl =& lookup_crl($crlref);
$cert = lookup_cert($certref);

if (!$crl['caref'] || !$cert['caref']) {
    echo "Both the Certificate and CRL must be specified.\r\n";
    die(1);
}

if ($crl['caref'] != $cert['caref']) {
    echo "CA mismatch between the Certificate and CRL. Unable to Revoke.\r\n";
    die(1);
}

if (!is_crl_internal($crl)) {
    echo "Cannot revoke certificates for an imported/external CRL.\r\n";
    die(1);
}

cert_revoke($cert, $crl, $reason);
openvpn_refresh_crls();
vpn_ipsec_configure();
write_config("Revoked cert {$cert['descr']} in CRL {$crl['descr']}.");
echo "Certificate revoked";
exit;
