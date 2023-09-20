<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wordpressuser' );

/** Database password */
define( 'DB_PASSWORD', 'password' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',          'Cxj&S[k6YM,}5$ ,*K8dkRdKg7OTGP=6sGNYl;Bh^Q?{.c]j(Ber?T;#,bjQ+xyt' );
define( 'SECURE_AUTH_KEY',   '38pE6za~3^%F^Th W1o3eG:&.EvT>Fv6h6Sh7/o>7<N1V8hF]lSOC/u+g8Lu mp$' );
define( 'LOGGED_IN_KEY',     '@13~ue-;uKk#dBNsj<uNo?l$EVoMm-C@!U@&?}wj2|_]gpZ>=L0QT<W$7IHD_)ra' );
define( 'NONCE_KEY',         '>Bf6!0uYL`(XVhg],:W3(D7z>J3FBm@_mZD-ZalNkKi;$6NY7;xc@|.65x/VFU!b' );
define( 'AUTH_SALT',         'mRB{G_FB*a9nLRgDtal*gFIR[IL-*wFnOpw_f7#m&/9Ei-ji-wD,FPbxJ+Gz8l[`' );
define( 'SECURE_AUTH_SALT',  '}!c%`knVA@Uvw}D8j#|T<&q5qqW~is1#9nsLo5u&~U%chY$L_ME/#a&x3}%@`G|a' );
define( 'LOGGED_IN_SALT',    'fwHt8;/tL5J_!<gVAa#8j/5rY`[IH~fo oY>M5]?{6:h3=}6c=:2JrvO#[@R2M3J' );
define( 'NONCE_SALT',        'sH[TKljbo$!*@:)(?q2S|t|`:`Ia-*#56CUGdjKU]&WwUhvtjM~nM~U1R!jw30Md' );
define( 'WP_CACHE_KEY_SALT', 'nQ6#Tm+.7v}j5;[HhEjOSia2[>}v_|!vW#%NkpM+l:Owr*hofBWpu7VD<H[M6&1n' );


/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );


/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
