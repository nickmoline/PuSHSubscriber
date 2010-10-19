<?php

/**
 * Implement file-based storage backend for subscriptions.
 *
 * Variables passed in to the constructor must be accessible as public class
 * variables.
 */
class PSubscriptionFile implements PuSHSubscriptionInterface {
  public static $subscription_dir = './subscriptions';
  public static $subscriptions;

  /**
   * @param $domain
   *   A string that defines the domain in which the subscriber_id is unique.
   * @param $subscriber_id
   *   A unique numeric subscriber id.
   * @param $hub
   *   The URL of the hub endpoint.
   * @param $topic
   *   The topic to subscribe to.
   * @param $secret
   *   A secret key used for message authentication.
   * @param $status
   *   The status of the subscription.
   *   'subscribe' - subscribing to a feed.
   *   'unsubscribe' - unsubscribing from a feed.
   *   'subscribed' - subscribed.
   *   'unsubscribed' - unsubscribed.
   *   'subscribe failed' - subscribe request failed.
   *   'unsubscribe failed' - unsubscribe request failed.
   * @param $post_fields
   *   An array of the fields posted to the hub.
   */
  public function __construct($domain, $subscriber_id, $hub, $topic, $secret, $status = '', $callback_url, $verify_token, $lease_time) {
    $this->domain = $domain;
	$this->subscriber_id = $subscriber_id;
	$this->hub = $hub;
	$this->topic = $topic;
	$this->secret = $secret;
	$this->status = $status;
	$this->callback_url = $callback_url;
	$this->verify_token = $verify_token;
	$this->lease_time = $lease_time;
  }

  /**
   * Save a subscription.
   */
  public function save() {
	$filepath = self::get_filepath($this->domain, $this->subscriber_id);
	if(file_put_contents($filepath, $this->_toJSON(), LOCK_EX)) {
	  return true;
	} else {
	  return false;
	}
  }
  
  /**
   * Delete a subscription.
   */
  public function delete() {
    $filepath = self::get_filepath($this->domain, $this->subscriber_id);
	if(is_readable($filepath)) {
	  if(unlink($filepath)) {
	    return true;
	  } else {
	    return false;
	  }
	} else {
	  return true;
	}
  }
  
  public function _toJSON() {
	$data = array(
		 'domain' => $this->domain,
		 'subscriber_id' => $this->subscriber_id,
		 'hub' => $this->hub,
		 'topic' => $this->topic,
		 'secret' => $this->secret,
		 'status' => $this->status,
		 'callback_url' => $this->callback_url,
		 'verify_token' => $this->verify_token,
		 'lease_time' => $this->lease_time
	);
	return json_encode($data);
  }
  
  public static _fromJSON($data) {
	$data = json_decode($data, true);
	$subscription = new PSubscriptionFile(
	  $data['domain'],
	  $data['subscriber_id'],
	  $data['hub'],
	  $data['topic'],
	  $data['secret'],
	  $data['status'],
	  $data['callback_url'],
	  $data['verify_token'],
	  $data['lease_time']
	);
	return $subscription;
  }
  
  public static function get_filepath($domain, $subscriber_id) {
	return self::$subscription_dir . '/' . $domain . '/' . $subscriber_id . '.pubsub';
  }
  /**
   * Load a subscription.
   *
   * @return
   *   A PuSHSubscriptionInterface object if a subscription exist, NULL
   *   otherwise.
   */
  public static function load($domain, $subscriber_id) {
    if(isset(self::$subscriptions[$domain][$subscriber_id])) {
	  return self::$subscriptions[$domain][$subscriber_id];
	} else {
	  $filepath = self::get_filepath($domain, $subscriber_id);
	  if(is_readable($filepath)) {
	    if($data = file_get_contents($filepath)) {
		  $sub = self::_fromJSON($data);
		  self::$subscriptions[$domain][$subscriber_id] = $sub;
		  return $sub;
	    } else {
	      return NULL;
	    }
	  } else {
        return NULL;
      }
	}
  }

}

?>