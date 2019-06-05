<?php
/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */
if (empty($argc)) {
    echo "Only accessible from the CLI.\r\n";
    die(1);
}
if ($argc != 3) {
    echo "Usage: php " . $argv[0] . " crlref certref\r\n";
    die(1);
}

require_once("certs.inc");
require_once("openvpn.inc");
require_once("pfsense-utils.inc");
require_once("vpn.inc");

$crlref = $argv[1];
$certref = $argv[2];

$thiscrl =& lookup_crl($crlref);

if (!is_array($thiscrl['cert'])) {
	echo "No certificate to revoke.\r\n";
	die(1);
}

$found = false;
foreach ($thiscrl['cert'] as $acert) {
	if ($acert['refid'] == $certref) {
		$found = true;
		$thiscert = $acert;
	}
}

if (!$found) {
	echo "Certificate is not revoked.\r\n";
	die(1);
}

$certname = htmlspecialchars($thiscert['descr']);
$crlname = htmlspecialchars($thiscrl['descr']);
if (cert_unrevoke($thiscert, $thiscrl)) {
	$savemsg = sprintf(gettext('Deleted Certificate %1$s from CRL %2$s.'), $certname, $crlname);
	echo $savemsg;
	// refresh IPsec and OpenVPN CRLs
	openvpn_refresh_crls();
	vpn_ipsec_configure();
	write_config($savemsg);
} else {
	$savemsg = sprintf(gettext('Failed to delete Certificate %1$s from CRL %2$s.'), $certname, $crlname);
	echo $savemsg;
	die(1);
}
