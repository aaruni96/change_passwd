<?php

/**
  * SquirrelMail Change Passwd Plugin
  * Copyright (C) 2004 Paul Lesneiwski <pdontthink@angrynerds.com>
  * Copyright (C) 2002 Thiago Melo de Paula <thiagomp@coc.com.br>
  * This program is licensed under GPL. See COPYING for details
  *
  */


function change_passwd_plugin_optpage_register_block_do()
{

// include compatibility plugin
//
if (defined('SM_PATH'))
   include_once(SM_PATH . 'plugins/compatibility/functions.php');
else if (file_exists('../plugins/compatibility/functions.php'))
   include_once('../plugins/compatibility/functions.php');
else if (file_exists('./plugins/compatibility/functions.php'))
   include_once('./plugins/compatibility/functions.php');



// make sure this plugin's configuration files are set up correctly
//
compatibility_check_plugin_setup('change_passwd', array('config.php'));


   global $optpage_blocks;


   bindtextdomain('change_passwd', SM_PATH . 'plugins/change_passwd/locale');
   textdomain('empty_folders');


   $optpage_blocks[] = array(
      'name' => _("Change Password"),
      'url'  => '../plugins/change_passwd/options.php',
      'desc' => _("Use this to change your email password."),
      'js'   => false
   );


   bindtextdomain('squirrelmail', SM_PATH . 'locale');
   textdomain('squirrelmail');

}

?>
