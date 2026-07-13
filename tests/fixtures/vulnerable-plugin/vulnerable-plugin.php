<?php
/**
 * Plugin Name: Vulnerable Test Fixture
 * Description: Intentionally vulnerable plugin used ONLY as a test fixture for
 *              the wp_plugin_security_scanner audit suite. Every handler below
 *              contains a real, known-bad pattern the scanners must detect.
 *              NEVER install on a live site.
 *
 * License: GPL-2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fixture 1 — unauthenticated AJAX handler with direct SQL injection.
 *
 * $user_id is taken straight from $_POST and concatenated into the query
 * string with no prepare(), no esc_sql(), no absint(). The handler has no
 * nonce and no capability check. wp_unauth_audit.py must flag this as
 * "interesting" (unauth + user input + raw sql, no guard).
 */
add_action( 'wp_ajax_nopriv_vtf_get_orders', 'vtf_get_orders' );
function vtf_get_orders() {
	global $wpdb;
	$user_id = $_POST['user_id'];
	$results = $wpdb->get_results(
		"SELECT * FROM {$wpdb->prefix}vtf_orders WHERE user_id = '" . $user_id . "'"
	);
	wp_send_json( $results );
}

/**
 * Fixture 2 — unauthenticated AJAX handler with reflected XSS.
 *
 * $msg is echoed verbatim with no esc_html(). wp_unauth_audit.py --xss must
 * flag this handler as xss_interesting.
 */
add_action( 'wp_ajax_nopriv_vtf_preview', 'vtf_preview' );
function vtf_preview() {
	$msg = $_POST['msg'];
	echo $msg;
	wp_die();
}

/**
 * Fixture 3 — REST route with permission_callback = __return_true whose
 * handler runs raw SQL on a request param. wp_rest_audit.py must flag the
 * route as unauth (public) AND taint (raw sql in the callback).
 */
add_action( 'rest_api_init', 'vtf_register_routes' );
function vtf_register_routes() {
	register_rest_route(
		'vtf/v1',
		'/lookup',
		array(
			'methods'             => 'GET',
			'callback'            => 'vtf_lookup',
			'permission_callback' => '__return_true',
		)
	);
}
function vtf_lookup( WP_REST_Request $request ) {
	global $wpdb;
	$key = $request->get_param( 'key' );
	return $wpdb->get_results(
		"SELECT * FROM {$wpdb->prefix}vtf_lookup WHERE lookup_key = '" . $key . "'"
	);
}

/**
 * Fixture 4 — SAFE handler (negative control). Same shape as Fixture 1 but
 * with absint() + prepare() + a capability check. No scanner should flag it.
 */
add_action( 'wp_ajax_nopriv_vtf_safe_lookup', 'vtf_safe_lookup' );
function vtf_safe_lookup() {
	if ( ! current_user_can( 'read' ) ) {
		wp_send_json_error( 'forbidden', 403 );
	}
	global $wpdb;
	$id = absint( $_POST['id'] );
	$results = $wpdb->get_results(
		$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}vtf_lookup WHERE id = %d", $id )
	);
	wp_send_json( $results );
}
