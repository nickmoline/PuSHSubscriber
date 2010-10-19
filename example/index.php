<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
	<meta http-equiv="Content-Type" content="text/html;charset=UTF-8" />
	<title></title>
</head>
<body>
<form action="" method="POST">
<input type="text" name="feed" id="feed" />
<input type="text" name="hub" id="hub" />
<input type="submit" value="Subscribe" />
</form>
	
</body>
</html>

<?php

include '../PuSHSubscriber.php';
include '../PSubscriptionFile.php';
include '../PEnvFile.php';

if(isset($_POST['feed'], $_POST['hub'])) {
	$domain = 'example_subs';
	$sub_id = (int)file_get_contents('./subscriptions/sub_number');
	$sub_id++;
	file_put_contents('./subscriptions/sub_number', $sub_id);
	
	$feed = $_POST['feed'];
	$hub = $_POST['hub'];
	
	// CHANGE THIS TO YOUR DOMAIN/PATH
	$callback_url = 'http://example.com/pubsub/example/index.php?domain='. $domain .'&sub_id='. $sub_id;
	
	
	$subber = PuSHSubscriber::instance($domain, $sub_id, 'PSubscriptionFile', new PEnvFile());

	$subber->subscribe($feed, $callback_url, $hub);

} elseif(isset($_GET['domain'], $_GET['sub_id'])) {

	handle_hub_callback($_GET['domain'], $_GET['sub_id']);

}

function handle_hub_callback($domain, $sub_id) {

	$subber = PuSHSubscriber::instance($domain, $sub_id, 'PSubscriptionFile', new PEnvFile());
	$subber->handleRequest('receive_notification');

}

function receive_notification($xml, $domain, $sub_id) {
	$data = "$domain :: $sub_id:\n". $xml . "\n\n";
	 file_put_contents('./logs/notifications.log', $data, FILE_APPEND|LOCK_EX);
}



?>

