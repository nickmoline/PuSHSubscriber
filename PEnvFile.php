<?php
/**
 * Implement to provide environmental functionality like user messages and
 * logging.
 */
class PEnvFile implements PuSHSubscriberEnvironmentInterface {
  public static $msg_file = './logs/messages.log';
  public static $log_file = './logs/system.log';
  /**
   * A message to be displayed to the user on the current page load.
   *
   * @param $msg
   *   A string that is the message to be displayed.
   * @param $level
   *   A string that is either 'status', 'warning' or 'error'.
   */
  public function msg($msg, $level = 'status') {
    $data = "$level :: $msg\n";
    file_put_contents(self::$msg_file, $data, FILE_APPEND|LOCK_EX);
  }

  /**
   * A log message to be logged to the database or the file system.
   *
   * @param $msg
   *   A string that is the message to be displayed.
   * @param $level
   *   A string that is either 'status', 'warning' or 'error'.
   */
  public function log($msg, $level = 'status') {
	$data = "$level :: $msg\n";
    file_put_contents(self::$log_file, $data, FILE_APPEND|LOCK_EX);
  }
  
}
?>