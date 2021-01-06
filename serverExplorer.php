<?php // see https://github.com/jimmybear217/serverExplorer

    // application settings
    $settings = array(
        "explorer" => array(
            "enabled" => true,
            "display_errors" => true,
            "use_remote_assets" => true,
            "assets_server" => "https://jimmybear217.dev/projects/repo/server_explorer/assets"
        ),
        "auth" => array(
            "require_auth" => true,
            "ip_whitelist" => array(
                "enabled" => false,
                "authorised_ips" => array()
            ),
            "user_password" => array(
                "enabled" => true,
                "server" => "https://jimmybear217.dev/projects/repo/server_explorer/userAuthServer.php"
            ),
            "app_password" => array(
                "enabled" => true,
                "hash" => password_hash("SuperSecurePassword", PASSWORD_BCRYPT)
            ),
            "2FA" => array(
                "enabled" => false,
                "server" => "https://jimmybear217.dev/projects/repo/server_explorer/2fa.php"
            )
        )
    );

    // logs
    if ($settings["explorer"]["display_errors"]) {
        error_reporting(E_ALL ^ E_NOTICE);
        ini_set('display_errors', 1);
    } else {
        error_reporting(0);
        ini_set('display_errors', 0);
    }

    // remote assets configuration
    $remote_assets = array(
        "favicon" => array(
            "actual" => $settings["explorer"]["assets_server"] . '/serverExplorer.png',
            "backup" => 'https://github.com/favicon.ico'
        ),
        "stylesheet" => $settings["explorer"]["assets_server"] . '/style.css',
        "logo" => $settings["explorer"]["assets_server"] . '/serverExplorer.png'
    );

    // pages content
    $pages = array(
        "camouflage"    => '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
                        . '<html><head><title>404 Not Found</title></head><body>'
                        . '<h1>Not Found</h1><p>The requested URL was not found on this server.</p>'
                        . ((!empty($_SERVER["SERVER_SIGNATURE"])) ? '<hr>' . $_SERVER["SERVER_SIGNATURE"] : "" )
                        . '</body></html>',
        "header"        => '<DOCTYPE HTML><html><head><title>Server Explorer</title><link rel="icon" src="'
                        . (($settings["explorer"]["use_remote_assets"]) ? $remote_assets["remote_assets"]["actual"] : $remote_assets["remote_assets"]["backup"])
                        . '">' . (($settings["explorer"]["use_remote_assets"]) ? '<link rel="stylesheet" src="' . $remote_assets["stylesheet"] . '">' : '')
                        . '</head><body><header><h1>' . (($settings["explorer"]["use_remote_assets"]) ? '<img src="' . $remote_assets["logo"] . '" height="32" width="32"> ' : '') . 'Server Explorer</h1></header>'
                        . '<div id="output">',
        "input"         => '</div><div id="input"><form action="' . $_SERVER["PHP_SELF"] . '?action=submit" method="POST">'
                        . '<input name="command" type="text" placeholder="$>"><input type="submit" value="send (or press enter)">'
                        . '</form>',
        "login"         => '<div id="login"><form action="' . $_SERVER["PHP_SELF"] . '" method="POST">'
                        . (($settings["auth"]["user_password"]["enabled"]) ? '<input name="username" placeholder="username" type="text">' : "")
                        . (($settings["auth"]["user_password"]["enabled"] || $settings["auth"]["app_password"]["enabled"]) ? '<input name="password" placeholder="password" type="password">' : "")
                        . '<input value="login (or press enter)" type="submit">',
        "footer"        => '</body></html>'
    );


    // check if system is enabled
    if (!$settings["explorer"]["enabled"]) {
        http_response_code(404);
        die($pages["camouflage"]);
    }

    // check if authentification is enabled
    if ($settings["auth"]["require_auth"]) {
        $login_state = false;
        // check 2FA
        if ($settings["auth"]["2FA"]["enabled"] && !$login_state){
            if (in_array("auth_2fa", $_COOKIE)) {
                if (empty($_COOKIE["auth_2fa"])) {
                    // send 2FA request
                    $token = file_get_contents($settings["auth"]["2FA"]["server"] . "?action=submit");
                    if (!empty($token) && strlen($token) < 300 && strlen($token) > 30) {
                        setcookie("auth_2fa", $token, time()+(60*60), $_SERVER["PHP_SELF"]);
                        $login_state = true;
                    }
                } else {
                    // check 2FA token
                    if (intval(file_get_contents($settings["auth"]["2FA"]["server"] . "?action=check&token=" . $_COOKIE["auth_2fa"])) != 1) {
                        $login_state = false;
                    }
                }
            }
        }
    }