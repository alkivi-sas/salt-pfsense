<?php
/*
 * vpn_openvpn_export.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2011-2015 Rubicon Communications, LLC (Netgate)
 * Copyright (C) 2008 Shrew Soft Inc
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("globals.inc");
#require_once("guiconfig.inc");
require_once("openvpn-client-export.inc");
require_once("pfsense-utils.inc");
require_once("pkg-utils.inc");
#require_once("classes/Form.class.php");
require_once("certs.inc");
require_once("openvpn.inc");
require_once("pfsense-utils.inc");
require_once("vpn.inc");

global $current_openvpn_version, $current_openvpn_version_rev, $legacy_openvpn_version, $legacy_openvpn_version_rev, $dyndns_split_domain_types;

$srvid = $argv[1];
$crtid = $argv[2];
$caref = $argv[3];
$addr = $argv[4];
$conf_type = $argv[5];

$ca =& lookup_ca($caref);

if (!$ca) {
    echo "Unable to find ca $caref.\r\n";
    die(1);
}


# We use only SSL based ...
$usrid = '';
$advancedoptions = base64_decode($config['installedpackages']['vpn_openvpn_export']['serverconfig']['item'][0]["advancedoptions"]);
$verifyservercn = 'auto';
$blockoutsidedns = '0';
$legacy = '0';
$randomlocalport = '0';
$usetoken = '0';
$usepkcs11 = '0';
$pkcs11providers = '';
$pkcs11id = '';
$silent = '1';
$bindmode = 'nobind';
$p12encryption = 'high';


$srvcfg = get_openvpnserver_by_id($srvid);

if ($srvid === false) {
    echo "srvid is false\r\n";
    die(1);
} else if (($srvcfg['mode'] != "server_user") &&
    (($usrid === false) || ($crtid === false))) {
    echo "server_user and no user\r\n";
    die(1);
}

if ($srvcfg['mode'] == "server_user") {
    $nokeys = true;
} else {
    $nokeys = false;
}

$useaddr = $addr;

if (!(is_ipaddr($useaddr) || is_hostname($useaddr) ||
    in_array($useaddr, array("serveraddr", "servermagic", "servermagichost", "serverhostname")))) {
    echo "unable to validate $useaddr.\r\n";
    die(1);
}


if ($usetoken && (substr($conf_type, 0, 10) == "confinline")) {
    echo "Microsoft Certificate Storage cannot be used with an Inline configuration.";
    die(1);
}
if ($usetoken && (($conf_type == "conf_yealink_t28") || ($conf_type == "conf_yealink_t38g") || ($conf_type == "conf_yealink_t38g2") || ($conf_type == "conf_snom"))) {
    echo "Microsoft Certificate Storage cannot be used with a Yealink or SNOM configuration.";
    die(1);
}
if ($usepkcs11 && !$pkcs11providers) {
    echo "You must provide the PKCS#11 providers.";
    die(1);
}
if ($usepkcs11 && !$pkcs11id) {
    echo "You must provide the PKCS#11 ID.";
    die(1);
}
$password = "";
if ($_POST['password']) {
    if ($_POST['password'] != DMYPWD) {
        $password = $_POST['password'];
    } else {
        $password = $cfg['pass'];
    }
}

$proxy = "";

$exp_name = openvpn_client_export_prefix($srvid, $usrid, $crtid);

if (substr($conf_type, 0, 4) == "conf") {
    switch ($conf_type) {
        case "confzip":
            $exp_name = urlencode($exp_name . "-config.zip");
            $expformat = "zip";
            break;
        case "conf_yealink_t28":
            $exp_name = urlencode("client.tar");
            $expformat = "yealink_t28";
            break;
        case "conf_yealink_t38g":
            $exp_name = urlencode("client.tar");
            $expformat = "yealink_t38g";
            break;
        case "conf_yealink_t38g2":
            $exp_name = urlencode("client.tar");
            $expformat = "yealink_t38g2";
            break;
        case "conf_snom":
            $exp_name = urlencode("vpnclient.tar");
            $expformat = "snom";
            break;
        case "confinline":
            $exp_name = urlencode($exp_name . "-config.ovpn");
            $expformat = "inline";
            break;
        case "confinlinedroid":
            $exp_name = urlencode($exp_name . "-android-config.ovpn");
            $expformat = "inlinedroid";
            break;
        case "confinlineios":
            $exp_name = urlencode($exp_name . "-ios-config.ovpn");
            $expformat = "inlineios";
            break;
        case "confinlinevisc":
            $exp_name = urlencode($exp_name . "-viscosity-config.ovpn");
            $expformat = "inlinevisc";
            break;
        default:
            $exp_name = urlencode($exp_name . "-config.ovpn");
            $expformat = "baseconf";
    }
    $exp_path = openvpn_client_export_config($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $nokeys, $proxy, $expformat, $password, $p12encryption, false, false, $advancedoptions, $usepkcs11, $pkcs11providers, $pkcs11id);
}

if ($conf_type == "visc") {
    $exp_name = urlencode($exp_name . "-Viscosity.visc.zip");
    $exp_path = viscosity_openvpn_client_config_exporter($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $password, $p12encryption, $proxy, $advancedoptions, $usepkcs11, $pkcs11providers, $pkcs11id);
}

if (substr($conf_type, 0, 4) == "inst") {
    $openvpn_version = substr($conf_type, 5);
    $exp_name = "openvpn-{$exp_name}-install-";
    switch ($openvpn_version) {
        case "x86-xp":
            $exp_name .= "{$legacy_openvpn_version}-I0{$legacy_openvpn_version_rev}-i686.exe";
            break;
        case "x64-xp":
            $exp_name .= "{$legacy_openvpn_version}-I0{$legacy_openvpn_version_rev}-x86_64.exe";
            break;
        case "x86-win6":
            $exp_name .= "{$legacy_openvpn_version}-I6{$legacy_openvpn_version_rev}-i686.exe";
            break;
        case "x64-win6":
            $exp_name .= "{$legacy_openvpn_version}-I6{$legacy_openvpn_version_rev}-x86_64.exe";
            break;
        case "24":
            $exp_name .= "{$current_openvpn_version}-I6{$current_openvpn_version_rev}.exe";
            break;
        case "Win7":
            $exp_name .= "{$current_openvpn_version}-I6{$current_openvpn_version_rev}-Win7.exe";
            break;
        case "Win10":
            $exp_name .= "{$current_openvpn_version}-I6{$current_openvpn_version_rev}-Win10.exe";
            break;
        default:
            $exp_name .= "{$current_openvpn_version}-I6{$current_openvpn_version_rev}.exe";
    }

    $exp_name = urlencode($exp_name);
    $exp_path = openvpn_client_export_installer($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $password, $p12encryption, $proxy, $advancedoptions, substr($conf_type, 5), $usepkcs11, $pkcs11providers, $pkcs11id, $silent);
}

if (($conf_type == "conf") || (substr($conf_type, 0, 10) == "confinline")) {
    $file = '/tmp/' . $exp_name;
    file_put_contents($file, $exp_path);
    $exp_path = $file;
}

if (!$exp_path) {
    echo "Failed to export config files!";
    die(1);
}

echo $exp_path;

exit;
