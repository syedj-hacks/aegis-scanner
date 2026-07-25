<?php
/*
 * xss.php — Aegis Scanner test-fixture companion script.
 *
 * NOT part of stock DVWA. The sibling of info.php (the SQLi fixture): DVWA's
 * own reflected-XSS lab page (vulnerabilities/xss_r/index.php) sits behind
 * DVWA's login wall, so Aegis's unauthenticated web-module flow can never
 * reach it. This page is a minimal, intentionally-vulnerable, UNAUTHENTICATED
 * reflected-XSS stand-in: the `name` GET parameter is echoed straight into
 * the HTML response with no output encoding, so nuclei's DAST XSS templates
 * (modules/web/xss_wrap.py) can confirm reflection end-to-end the same way
 * the scanner's real code path is supposed to work. Local, isolated,
 * authorized test target only.
 */

$name = isset($_GET['name']) ? $_GET['name'] : 'guest';

header('Content-Type: text/html; charset=UTF-8');
echo "<!DOCTYPE html><html><head><title>Aegis XSS test fixture</title></head><body>";
echo "<h1>Hello, $name!</h1>";
echo "<p>This unauthenticated page reflects the <code>name</code> parameter without encoding.</p>";
echo "</body></html>";
