<?php


/**
  * SquirrelMail Change Passwd Plugin
  * Copyright (C) 2004 Paul Lesneiwski <pdontthink@angrynerds.com>
  * Copyright (C) 2002 Thiago Melo de Paula <thiagomp@coc.com.br>
  * This program is licensed under GPL. See COPYING for details
  *
  */


function squirrelmail_plugin_init_change_passwd() 
{

   global $squirrelmail_plugin_hooks;

   $squirrelmail_plugin_hooks['optpage_register_block']['change_passwd'] 
      = 'change_passwd_plugin_optpage_register_block';

}



if (!defined('SM_PATH'))
   define('SM_PATH', '../');



function change_passwd_plugin_optpage_register_block() 
{

   include_once(SM_PATH . 'plugins/change_passwd/functions.php');
   change_passwd_plugin_optpage_register_block_do();

}



function change_passwd_version() 
{
   return '4.0';
}



?>
