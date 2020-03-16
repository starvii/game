<?php
define("TIMEOUT", 15);
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!(
        isset($_POST["username"])
        && isset($_POST["password"])
        && isset($_POST["validcode"])
        && isset($_POST["submit"])
    )) {
        die("参数错误。");
    }
    if (!isset($_SESSION["timeout"]) || time() > $_SESSION["timeout"]) {
        die("会话超时。请重新登录。");
    }
    if (intval($_POST["validcode"]) != $_SESSION["validcode"]) {
        die("验证码错误。");
    }
    if ($_POST["username"] != "admin" && $_POST["password"] != "12345678") {
        die("用户名或密码错误。");
    }
    echo "登录成功。<br/>";
    system("cat /tmp/flag.txt");
    // file_get_contents("/tmp/flag.txt");
    exit(0);
} elseif ($_SERVER["REQUEST_METHOD"] == "GET") {
    // to continue
} else {
    die("非法HTTP方法。");
}
?>

<?php
$a = random_int(100, 1000);
$b = random_int(100, 1000);
$_SESSION["validcode"] = $a + $b;
$_SESSION["timeout"] = time() + TIMEOUT;
?>
<!doctype html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>登陆</title>
    </head>
    <body>
        <form name="login" method="post">
            <p>用户名：<input type=text name="username"></p>
            <p>密　码：<input type=password name="password"></p>
            <p>
            <span><?php echo "$a + $b = ?";?></span><br/>
            验证码：<input type=text value="" name="validcode">
            </p>
            <p><input type="submit" name="submit" value="登录"></p>
        </form>
    </body>
</html>
