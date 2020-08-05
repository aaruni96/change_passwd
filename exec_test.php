<html><body>
<?php

   // test using URL similar to:
   // 
   // http://domain.com/squirrelmail/plugins/change_passwd/exec_test.php
   //
   echo "Testing exec()...<br />";
   echo "safe_mode = " . ini_get('safe_mode') . "<br />";
   echo "safe_mode_exec_dir = " . ini_get('safe_mode_exec_dir') . '<br />';
   //echo "error_reporting = " . ini_get('error_reporting') . "<br />";
   //echo "display_errors = " . ini_get('display_errors') . "<br />";
   echo "<hr />";
   exec('ls 2>&1', $out, $ret);
   echo "return value = $ret<br /><br />output:<pre>";
   print_r($out);
   echo "</pre>";

?>
</body></html>
