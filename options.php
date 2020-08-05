<?php

/**
  * SquirrelMail Change Passwd Plugin
  * Copyright (C) 2004 Paul Lesneiwski <pdontthink@angrynerds.com>
  * Copyright (C) 2002 Thiago Melo de Paula <thiagomp@coc.com.br>
  * This program is licensed under GPL. See COPYING for details
  *
  */


chdir('..');
define('SM_PATH','../');


// include compatibility plugin
//
if (defined('SM_PATH'))
   include_once(SM_PATH . 'plugins/compatibility/functions.php');
else if (file_exists('../plugins/compatibility/functions.php'))
   include_once('../plugins/compatibility/functions.php');
else if (file_exists('./plugins/compatibility/functions.php'))
   include_once('./plugins/compatibility/functions.php');



global $disconn, $confirmNewPass, $confirmOldPass, $compatibility_sm_path,
       $seeOutput, $overridePathToChpasswd, $pathToPw, $debug, $minimumPasswordLength;


if (compatibility_check_sm_version(1, 3))
{
   include_once (SM_PATH . 'plugins/change_passwd/config.php');
   include_once (SM_PATH . 'include/validate.php');
}
else
{
   include_once ('../plugins/change_passwd/config.php');
   include_once ('../src/validate.php');
}



global $gochange, $user, $old_pw, $new_pw1, $new_pw2,
       $base_uri, $onetimepad, $key, $username;


compatibility_sqextractGlobalVar('gochange');
//compatibility_sqextractGlobalVar('user');
compatibility_sqextractGlobalVar('old_pw');
compatibility_sqextractGlobalVar('new_pw1');
compatibility_sqextractGlobalVar('new_pw2');
compatibility_sqextractGlobalVar('base_uri');
$gochange = trim($gochange);
//$user = trim($user);
$user = $username;  // don't need to cycle this thru the form, only makes it less secure
$old_pw = trim($old_pw);
$new_pw1 = trim($new_pw1);
$new_pw2 = trim($new_pw2);
$base_uri = trim($base_uri);


bindtextdomain('change_passwd', SM_PATH . 'plugins/change_passwd/locale');
textdomain('empty_folders');


if (isset($gochange) && $gochange) 
{

   //
   // verify input
   //



   // check for empty values
   //
   if (empty($user))
   {
      $msg = _("Could not determine your username.") . ' ' 
           . _("Please contact your system administrator.");
      $gochange = 0;
   }
   else if ($confirmOldPass && empty($old_pw))
   {
      $msg = _("Please enter your current password.");
      $gochange = 0;
   }
   else if (empty($new_pw1))
   {
      $msg = _("Please enter your new password.");
      $gochange = 0;
   }
   else if ($confirmNewPass && empty($new_pw2))
   {
      $msg = _("Please re-enter your new password.");
      $gochange = 0;
   }


   // check for minimum password length
   //
   else if ($minimumPasswordLength > 0 && strlen($new_pw1) < $minimumPasswordLength)
   {
      $msg = sprintf(_("Your new password must be at least %s characters long."), 
                     $minimumPasswordLength);
      $gochange = 0;
   }


   // make sure new passwords are the same
   //
   else if ($confirmNewPass) 
   {
      if ($new_pw1 != $new_pw2)  
      {
         $msg = _("The confirmation of your new password did not match.");
         $gochange = 0;
      }
   }



   // if everything else was OK, make sure old (current) 
   // password is correct
   //
   if ($gochange)
   {
      // get global variable for versions of PHP < 4.1
      //
      if (!compatibility_check_php_version(4,1)) {
         global $HTTP_COOKIE_VARS;
         $_COOKIE = $HTTP_COOKIE_VARS;
      }
      $key = $_COOKIE['key'];
      compatibility_sqextractGlobalVar('onetimepad');

      $currentPassword = OneTimePadDecrypt($key, $onetimepad);

      if ($currentPassword != $old_pw)
      {
         $msg = _("Your current password is not correct.");
         // debugging... $msg .= "<br />$currentPassword<br />$old_pw<br />";
         $gochange = 0;
      }
   }



   // sanitize input for use in exec()
   //
   $safe_newpw = escapeshellarg($new_pw1);
   $safe_oldpw = escapeshellarg($old_pw);
   $safe_user = escapeshellarg($user);



   // if we got this far, we can proceed with the password update
   //
   if ($gochange)
   {


      // use pw utility (FreeBSD)
      //
      if (! empty($pathToPw)) 
      {
         $fd = popen("$pathToPw usermod $safe_user -h 0 2>&1", 'w+');
         fwrite($fd, $safe_newpw);
         $ret = fread($fd, 4096);
         pclose($fd);                
      }


      // otherwise, use chpasswd
      //
      else
      {

         // use chpasswd in plugin directory
         //
         if (empty($overridePathToChpasswd))
         {
            $cmd = $compatibility_sm_path . "plugins/change_passwd/chpasswd $safe_user $safe_oldpw $safe_newpw 2>&1";
         }

   
         // use chpasswd elsewhere
         //
         else
            $cmd = "$overridePathToChpasswd $safe_user $safe_oldpw $safe_newpw";


         // print out the command for debugging
         //
         if ($debug)
         {
            echo '<br /><hr />To test the chpasswd utility from the command line, do this:<br /><br />' 
               . '<pre>cd ' . getcwd() . '</pre><pre>'
               . $cmd . '</pre><br /><hr />';
            exit;
         }

         exec($cmd, $capt, $ret);

      }



      if (!$ret)
      {

         $msg = _("Your password was changed successfully.");

         // write new cookies for the password
         //
         $onetimepad = OneTimePadCreate(strlen($new_pw1));
         compatibility_sqsession_register($onetimepad, 'onetimepad');
         $key = OneTimePadEncrypt($new_pw1, $onetimepad);
         setcookie('key', $key, 0, $base_uri);

      } 
      else
      { 

         $status = array(
                     0 => _("The password was modified successfully"),
                     2 => _("Missing new password"),
                     3 => _("Missing current password"),
                     4 => sprintf(_("The password for this user cannot be changed due to security constraints: %s"), $user),
                     5 => _("The new password is equal to the current password. Choose another password."),
                     6 => _("Could not read password file"),  // not using shadow pwd file
                     7 => _("Could not read password file"),  // using shadow pwd file
                     8 => _("Temporary file could not be opened"),
                     9 => _("Current password is incorrect"),
                    10 => sprintf(_("User does not exist: %s"), $user),
                    11 => _("Virtual memory exhausted"),
                    12 => _("Missing username"),
                        );

         if (isset($status[$ret]))
            $msg = $status[$ret];
         else
            $msg = _("An error has occurred while attempting to change your password.") . ' '
                 . _("Please contact your system administrator.");

      }


      if ($seeOutput)
      {

         $msg .= '<br />' . _("Command output:") . ' ';

         for ($i = 0; $i < count($capt); $i++)
            $msg .= '<br />' . _($capt[$i]);

         $msg .= '<br />' . _("Return code:") . ' ' . $ret;

      }

   }

}


displayPageHeader($color, 'None');


?>
<br />
<table width="95%" align="center" border="0" cellpadding="2" cellspacing="0">
  <tr>
    <td align="center" bgcolor="<?php echo $color[3] ?>"><b><?php echo _("Change Password"); ?></b>
      <table cellspacing="0" cellpadding="0" border="0" width="99%">
        <tr>
          <td bgcolor="<?php echo $color[9] ?>">

            <?php 

               if (isset($msg))
                  echo "<table cellspacing=\"5\"><tr><td><b><font color=\"red\">$msg</font></b></td></tr></table>";
               echo '&nbsp;&nbsp;' 
                    . _("Please read the following instructions before editing your password:")
                    . '<ul>'
                    . '<li>' 
                    . _("You may use letters, numbers, and other special characters on your keyboard.")
                    . '<li>'
                    . _("Passwords are case-sensititve, so an 'A' is not the same as an 'a'.");

               if ($minimumPasswordLength > 0)
                  echo '<li>'
                       . sprintf(_("Your new password must be at least %s characters long."), 
                                 $minimumPasswordLength);

// add other criteria...
//               echo '<li>'
//                    . _("Your new password must contain at least three (3) letters (a-z) and two (2) digits (0-9).");

               echo '</ul>';

            ?>

            <form method="post">
              <input type="hidden" name="gochange" value="1" />
              <center>
                <hr noshade />
                <table>
                  <tr>
                    <td align="right"><?php echo _("Your user name:"); ?></td> 
                    <td><b><?php echo $username?></b>
                      <input type="hidden" name="user" value="<?php echo $username; ?>" />
                    </td>
                  </tr>
        <?php if ($confirmOldPass) { ?>
                  <tr>
                    <td align="right"><?php echo _("Current password:"); ?> </td>
                    <td><input name="old_pw" size="10" type="password" maxlength="50" /> </td>
                  </tr>
        <?php }?>
                  <tr>
                    <td align="right"><?php echo _("New password:"); ?> </td>
                    <td><input name="new_pw1" size="10" type="password" maxlength="50" /> </td>
                  </tr>
        <?php if ($confirmNewPass) { ?>
                  <tr>
                    <td align="right"><?php echo _("Confirm new password:"); ?> </td>
                    <td><input name="new_pw2" size="10" type="password" maxlength="50" /></td>
                  </tr>
        <?php }?>
                </table>
                <hr noshade />
                <input name="change" type="submit" value="<?php echo _("Change Password"); ?>" />
              </center>
            </form> 
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>

<?php
   bindtextdomain('squirrelmail', SM_PATH . 'locale');
   textdomain('squirrelmail');
?>
