<?php
/*
This file is part of github-wrike-sync.

github-wrike-sync is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

github-wrike-sync is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with github-wrike-sync.  If not, see <http://www.gnu.org/licenses/>.
*/


/**
 * Wrike API abstraction.
 *
 * Provides the ability to add/update/delete wrike tasks, folders && comments
 * via github service webhooks.
 *
 * @param string $secret Required. Wrike oAuth secret.
 * @param string $consumer Required. Wrike oAuth key.
 * @param string $access_token Required. Wrike oAuth access access token.
 * @param string $access_token_secret Required. Wrike oAuth access token secret.
 * 
 */
	 
class LN_WRIKE {
    
    protected $secret 				= '';
	protected $consumer 			= '';
    protected $access_token 		= '';
    protected $access_token_secret 	= '';
    
    // set user's github id as key / wrike id as value
    // this allows us to set responsible users for wrike tasks
    // check out: http://caius.github.io/github_id/
    protected $github_user_ids = array(
    				'Dev #1 Github ID'	=> 'Dev #1 Wrike ID',	//User 1
    				'Dev #2 Github ID'	=> 'Dev #2 Wrike ID',	//User 2, etc..
    			);

    public function __construct($secret, $consumer, $token, $token_secret){
        $this->secret 				= $secret;
        $this->consumer 			= $consumer;
        $this->access_token 		= $token;
        $this->access_token_secret 	= $token_secret;
    }
    	
	private function urlencode_rfc3986($string) {
		return str_replace("%7E", "~", rawurlencode($string));
	}
	
	/**
	 * Wrike global API call.
	 *
	 * @param string $url Required. Wrike API URL.
	 * @param array $authParams Required. Params to be sent in wrike API call.
	 * @param string $token_secret Required. Wrike oAuth access token secret.
	 * @param string $method Optional. Request Method.
	 * @return curl response
	 * 
	 */
	private function makeAPICall($url, $params = array(), $token_secret = "", $method = "GET") {
		$consumer = $this->consumer;
		$secret = $this->secret;
		
		$authParams = array(
			"oauth_consumer_key" => $consumer,
			"oauth_nonce" => md5(microtime() . mt_rand()),
			"oauth_signature_method" => "HMAC-SHA1",
			"oauth_timestamp" => time(),
			"oauth_token" => $this->access_token,
			"oauth_version" => "1.0"
		);
		
		if ( !empty($params) ) $authParams = array_merge($authParams, $params);
		
		// sort arguments by key name before calculating signature
		ksort($authParams);
	
		$query_string = "";
		foreach($authParams as $key => $value) {
			$query_string .= $key . "=" . $this->urlencode_rfc3986($value) . "&";
		}
		$query_string = rtrim($query_string, "&");
		$key_parts = array(
			$this->urlencode_rfc3986($secret), 
			$token_secret != ""? $this->urlencode_rfc3986($token_secret): ""
		);
		$params = array(
			$method, 
			$this->urlencode_rfc3986($url), 
			$this->urlencode_rfc3986($query_string)
		);
		$base_string = implode("&", $params);
		$signature = base64_encode(hash_hmac("sha1", $base_string, implode("&", $key_parts), true));
		
		$authParams["oauth_signature"] = $signature;
		
		$query_string = "";
		foreach($authParams as $key => $value) {
			$query_string .= $key . "=" . $this->urlencode_rfc3986($value) . "&";
		}
		$query_string = rtrim($query_string, "&");
		
		//echo $query_string;
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt( $ch, CURLOPT_HEADER, true);
		if ($method == "GET") {
			curl_setopt($ch, CURLOPT_URL, $url . "?" . $query_string);
		}
		else {
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
		}
		$result = curl_exec($ch);
		curl_close($ch);
		
		return $result;
	}
	
	
	/**
	 * Wrike Request Token API call.
	 *
	 * Allows user to log in to wrike and authorize app
	 * 
	 */
	public function getRequestToken() {
		$consumer = $this->consumer;
		
		$url = "https://www.wrike.com/rest/auth/request_token"; 
		$params = array(
			"oauth_callback" => '',
			"oauth_consumer_key" => $consumer,
			"oauth_nonce" => md5(microtime() . mt_rand()),
			"oauth_signature_method" => "HMAC-SHA1",
			"oauth_timestamp" => time(),
			"oauth_version" => "1.0"
		); 
		$result = $this->makeAPICall($url, $params);
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		list($token, $token_secret) = explode("&", $body);
		list($label, $token) = explode("=", $token);
		list($label, $token_secret) = explode("=", $token_secret);
	
		// redirect to auth page
		$callback_url = "https://" . $_SERVER["HTTP_HOST"] . dirname($_SERVER["REQUEST_URI"]) . "/zgwtest.php?oauth_token=" . $token . "&oauth_token_secret=" . $token_secret;
		header("Location: https://www.wrike.com/rest/auth/authorize?oauth_token=" . $token . "&oauth_callback=" . $this->urlencode_rfc3986($callback_url));
	}
	
	
	/**
	 * Wrike Access Token API call.
	 *
	 * @param string $token Required. Wrike access token.
	 * @param string $secret Required. Wrike access token secret.
	 * @return curl response
	 * 
	 */
	public function getAccessToken($token, $secret) {
		$consumer = $this->consumer;
		
		$url = "https://www.wrike.com/rest/auth/access_token";
		$params = array(
			"oauth_consumer_key" => $consumer,
			"oauth_nonce" => md5(microtime() . mt_rand()),
			"oauth_signature_method" => "HMAC-SHA1",
			"oauth_timestamp" => time(),
			"oauth_token" => $token,
			"oauth_version" => "1.0"
		);
		$result = $this->makeAPICall($url, $params, $secret);
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		list($access_token, $access_token_secret) = explode("&", $body);
		list($label, $access_token) = explode("=", $access_token);
		list($label, $access_token_secret) = explode("=", $access_token_secret);
	
		$_url = "http://" . $_SERVER["HTTP_HOST"] . dirname($_SERVER["REQUEST_URI"]) . "/zgwtest.php?access_token=" . $access_token . "&access_token_secret=" . $access_token_secret;
		//header("Location: " . $_url);
		
		echo 'access_token:' . $access_token . '</br> access_token_secret:' . $access_token_secret;
	}
	
	
	/**
	 * Wrike My Profile API call.
	 *
	 * Allows user to pull their own profile data from wrike api.
	 * @return response body (typically a json string)
	 * 
	 */
	public function getMyProfile() {
		$url = "https://www.wrike.com/api/json/v2/wrike.profile.get";
		$params = array();
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Accounts list API call.
	 *
	 * Allows user to pull all attached accounts from wrike api.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getAccounts() {
		$url = "https://www.wrike.com/api/json/v2/wrike.accounts.list";
		$params = array();
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Contacts API call.
	 *
	 * Allows user to pull contacts data from wrike api.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getContacts() {
		$url = "https://www.wrike.com/api/json/v2/wrike.contacts.list";
		$params = array();
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Folders list API call.
	 *
	 * Allows user to pull folder list from wrike api.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getFolders() {
		$url = "https://www.wrike.com/api/json/v2/wrike.folder.tree";
		$params = array();
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Folder API call.
	 *
	 * Allows user to pull specific folder data from wrike api.
	 *
	 * @param string $id Required. Wrike Folder ID.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getFolder($id = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.folder.get";
		$params = array();
		
		if ( $id ) 			$params['id'] 		= $id;
		if ( $asyncKey ) 	$params['asyncKey'] = $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Add Folder API call.
	 *
	 * Allows user to add specific folder data via wrike api.
	 *
	 * @param string $title Required. Wrike Folder Title.
	 * @param string $description Optional. Wrike Folder Description.
	 * @param string $sharedUsers Optional. Comma Separated List of Wrike User IDs to share folder.
	 * @param string $parents Optional. Comma Separated List of Wrike parent folder IDs.
	 * @param string $account Optional. Wrike account ID.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function addFolder($title = false, $description = false, $sharedUsers = false, $parents = false, $account = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.folder.add";
		$params = array();
		
		if ( $title ) 		$params['title'] 		= $title;
		if ( $description ) $params['description'] 	= $description;
		if ( $sharedUsers ) $params['sharedUsers'] 	= $sharedUsers;
		if ( $parents ) 	$params['parents'] 		= $parents;
		if ( $account ) 	$params['account'] 		= $account;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Update Folder API call.
	 *
	 * Allows user to update specific folder data via wrike api.
	 *
	 * @param string $id Required. Wrike Folder ID.
	 * @param string $title Required. Wrike Folder Title.
	 * @param string $description Optional. Wrike Folder Description.
	 * @param string $sharedUsers Optional. Comma Separated List of Wrike User IDs to share folder.
	 * @param string $parents Optional. Comma Separated List of Wrike parent folder IDs.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function updateFolder($id = false, $title = false, $description = false, $sharedUsers = false, $parents = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.folder.update";
		$params = array();
		
		if ( $id ) 			$params['id'] 			= $id;
		if ( $title ) 		$params['title'] 		= $title;
		if ( $description ) $params['description'] 	= $description;
		if ( $sharedUsers ) $params['sharedUsers'] 	= $sharedUsers;
		if ( $parents ) 	$params['parents'] 		= $parents;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Delete Folder API call.
	 *
	 * Allows user to delete specific folders via wrike api.
	 *
	 * @param string $ids Required. Comma Separated List of Wrike Folder IDs.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function deleteFolder($ids = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.folder.delete";
		$params = array();
		
		if ( $id ) 		$params['ids'] 		= $ids;
		if ( $asyncKey ) 	$params['asyncKey'] = $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	
/*
	
	Task Rules and specifications

		A task can be included in several parent folders.
		A task cannot be simultaneously included in the root and the parent folder.
		
		Statuses
			0 - active
			1 - completed
			2 - deferred
			3 - canceled
		
		Importance
			0 - high
			1 - normal
			2 - low
	
		Dates and duration	
			backlog - no start date, no due date, duration
			milestone - no start date, no duration, only due date
			planned - start date, due date, duration
		
		relationType
			0 - author
			1 - responsible
			2 shared 
			(by default all - 0,1,2)
		
		
		example:
			"statuses" => "0",
			"relationType" => 1,
			"fields" => "id,title"
		
*/
	
	
	/**
	 * Wrike Get Task API call.
	 *
	 * Allows user to pull specific task data via wrike api.
	 *
	 * @param string $id Required. Wrike Task ID.
	 * @param string $fields Optional. Wrike task fields to filter by.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getTask($id = false, $fields = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.task.get";
		$params = array();
		
		if ( $id ) 			$params['id'] 		= $id;
		if ( $fields )		$params['fields']	= $fields; 
		if ( $asyncKey ) 	$params['asyncKey'] = $asyncKey;
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Get Tasks API call.
	 *
	 * Allows user to pull all tasks via wrike api.
	 *
	 * @param string $fields Optional. Wrike task fields to filter by.
	 * @param string $limit Optional. Number of tasks in response.
	 * @param string $offset Optional. number of tasks to skip before returning a response.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getTasks($fields = false, $limit = false, $offset = false, $asyncKey = false) {
		$consumer = $this->consumer;
		
		$url = "https://www.wrike.com/api/json/v2/wrike.task.filter";
		$params = array();
		
		if ( $fields )		$params['fields']	= $fields;
		if ( $limit )		$params['limit']	= $limit; 
		if ( $offset )		$params['offset']	= $offset;
		if ( $asyncKey ) 	$params['asyncKey'] = $asyncKey;
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Add Task API call.
	 *
	 * Allows user to add task via wrike api.
	 *
	 * @param string $title Required. Wrike task title.
	 * @param string $description Optional. Wrike task description.
	 * @param string $status Optional. Wrike task status.
	 * @param string $importance Optional. Wrike task importance.
	 * @param string $startDate Optional. Wrike task start date. ( yyyy-MM-dd'T'HH:mm:ss )
	 * @param string $dueDate Optional. Wrike task due date. ( yyyy-MM-dd'T'HH:mm:ss )
	 * @param string $duration Optional. Wrike task duration
	 * @param string $responsibleUsers Optional. Comma Separated List of Wrike User IDs responsible for this task.
	 * @param string $sharedUsers Optional. Comma Separated List of Wrike User IDs who share (view) this task.
	 * @param string $parents Optional. Comma Separated List of Wrike Folder IDs which are parents of this task.
	 * @param string $account Optional. Wrike account ID.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function addTask($title = false, $description = false, $status = false, $importance = false, $startDate = false, $dueDate = false, $duration = false, $responsibleUsers = false, $sharedUsers = false, $parents = false, $account = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.task.add";
		$params = array();
		
		if ( $responsibleUsers && !empty($this->github_user_ids[$responsibleUsers]) ) $responsibleUsers = $this->github_user_ids[$responsibleUsers]; 
		
		if ( $title ) 				$params['title'] 			= $title;
		if ( $description ) 		$params['description'] 		= $description;
		if ( $status ) 				$params['status'] 			= $status;
		if ( $importance ) 			$params['importance'] 		= $importance;
		if ( $startDate ) 			$params['startDate'] 		= $startDate;
		if ( $dueDate ) 			$params['dueDate'] 			= $dueDate;
		if ( $duration ) 			$params['duration'] 		= $duration;
		if ( $responsibleUsers ) 	$params['responsibleUsers'] = $responsibleUsers;
		if ( $sharedUsers ) 		$params['sharedUsers'] 		= $sharedUsers;
		if ( $parents ) 			$params['parents'] 			= $parents;
		if ( $account ) 			$params['account'] 			= $account;
		if ( $asyncKey ) 			$params['asyncKey'] 		= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Update Task API call.
	 *
	 * Allows user to update task via wrike api.
	 *
	 * @param string $id Required. Wrike task ID.
	 * @param string $title Required. Wrike task title.
	 * @param string $description Optional. Wrike task description.
	 * @param string $status Optional. Wrike task status.
	 * @param string $importance Optional. Wrike task importance.
	 * @param string $startDate Optional. Wrike task start date. ( yyyy-MM-dd'T'HH:mm:ss )
	 * @param string $dueDate Optional. Wrike task due date. ( yyyy-MM-dd'T'HH:mm:ss )
	 * @param string $duration Optional. Wrike task duration
	 * @param string $responsibleUsers Optional. Comma Separated List of Wrike User IDs responsible for this task.
	 * @param string $sharedUsers Optional. Comma Separated List of Wrike User IDs who share (view) this task.
	 * @param string $parents Optional. Comma Separated List of Wrike Folder IDs which are parents of this task.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function updateTask($id = false, $title = false, $description = false, $status = false, $importance = false, $startDate = false, $dueDate = false, $duration = false, $responsibleUsers = false, $sharedUsers = false, $parents = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.task.update";
		$params = array();
		
		if ( $responsibleUsers && !empty($this->github_user_ids[$responsibleUsers]) ) $responsibleUsers = $this->github_user_ids[$responsibleUsers];
		
		if ( $id ) 					$params['id'] 				= $id;
		if ( $title ) 				$params['title'] 			= $title;
		if ( $description ) 		$params['description'] 		= $description;
		if ( $status ) 				$params['status'] 			= $status;
		if ( $importance ) 			$params['importance'] 		= $importance;
		if ( $startDate ) 			$params['startDate'] 		= $startDate;
		if ( $dueDate ) 			$params['dueDate'] 			= $dueDate;
		if ( $duration ) 			$params['duration'] 		= $duration;
		if ( $responsibleUsers ) 	$params['responsibleUsers'] = $responsibleUsers;
		if ( $sharedUsers ) 		$params['sharedUsers'] 		= $sharedUsers;
		if ( $parents ) 			$params['parents'] 			= $parents;
		if ( $asyncKey ) 			$params['asyncKey'] 		= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Delete Tasks API call.
	 *
	 * Allows user to delete tasks via wrike api.
	 *
	 * @param string $ids Required. Comma Separated List of Wrike task IDs to be deleted.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function deleteTask($ids = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.task.delete";
		$params = array();
		
		if ( $ids )			$params['ids']		= $ids;
		if ( $asyncKey ) 	$params['asyncKey'] = $asyncKey;
		
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Get Comments API call.
	 *
	 * Allows user to pull all comments for a specific task via wrike api.
	 *
	 * @param string $taskId Optional. Wrike task ID to pull comments from.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function getComments($taskId = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.comment.list";
		$params = array();
		
		if ( $taskId ) 		$params['taskId'] 		= $taskId;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Add Comment API call.
	 *
	 * Allows user to add comment via wrike api.
	 *
	 * @param string $taskId Required. Wrike task ID.
	 * @param string $text Required. Wrike comment text.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function addComment($taskId = false, $text = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.comment.add";
		$params = array();
		
		if ( $taskId ) 		$params['taskId'] 		= $taskId;
		if ( $text ) 		$params['text'] 		= $text;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Update Comment API call.
	 *
	 * Allows user to update comment via wrike api.
	 *
	 * @param string $id Required. Wrike comment ID.
	 * @param string $text Required. Wrike comment text.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function updateComment($id = false, $text = false, $asyncKey = false) {
		$url = "https://www.wrike.com/api/json/v2/wrike.comment.update";
		$params = array();
		
		if ( $id ) 			$params['id'] 			= $id;
		if ( $text ) 		$params['text'] 		= $text;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Delete Comment API call.
	 *
	 * Allows user to delete comment via wrike api.
	 *
	 * @param string $ids Required. Comma Separated List of Wrike comment IDs to be removed.
	 * @param string $asyncKey Optional. oAuth async key.
	 * @return response body (typically a json string)
	 * 
	 */
	private function deleteComment($ids = false, $asyncKey = false) {		
		$url = "https://www.wrike.com/api/json/v2/wrike.comment.delete";
		$params = array();
		
		if ( $ids ) 		$params['ids'] 			= $ids;
		if ( $asyncKey ) 	$params['asyncKey'] 	= $asyncKey;
		 
		$result = $this->makeAPICall($url, $params, $this->access_token_secret, "POST");
	
		list($headers, $body) = explode("\r\n\r\n", $result, 2);
		
		return $body;
	}
	
	
	/**
	 * Wrike Github Sync Method.
	 *
	 * Pulls data from github webhook and syncs github milestones, issues && comments with Wrike
	 * 		|GITHUB|		|WRIKE|
	 *		milestone	==	folder
	 *		issue		==	task
	 *		comment		==	comment
	 *
	 * @param string $json Required. GitHub JSON POST DATA from webhook.
	 * @return array Wrike API responses 
	 * 
	 */
	public function github_sync($json) { 
		$github = json_decode($json);
		if ( empty($github) ) return false;
		//echo '<pre>'; print_r($github); die();
		
		$wrikeResponses = array();
		
		if ( !empty($github->action) ) {
			//github returns pull requests as issues, but we dont want those here
			if ( !empty($github->issue) && empty($github->issue->pull_request->html_url) ) {
				$issue 					= new stdClass();
				$issue->gid 			= $github->issue->id;
				$issue->gnum			= $github->issue->number;
				$issue->title			= $github->issue->title;
				$issue->status			= ( ( !empty($github->issue->state) ) ? ( ($github->issue->state == 'open') ? '0' : ( ($github->issue->state == 'closed') ? '1' : '2' ) ) : '0' );
				$issue->milestone_id 	= ( ( !empty($github->issue->milestone) && !empty($github->issue->milestone->id) ) ? $github->issue->milestone->id : '' );
				$issue->milestone_num 	= ( ( !empty($github->issue->milestone) && !empty($github->issue->milestone->number) ) ? $github->issue->milestone->number : '' );
				$issue->milestone_title = ( ( !empty($github->issue->milestone) && !empty($github->issue->milestone->title) ) ? $github->issue->milestone->title : '' );
				$issue->creator			= $github->issue->user;
				$issue->assignee		= ( (!empty($github->issue->assignee) && !empty($github->issue->assignee->id)) ? $github->issue->assignee->id : false );
				$issue->description		= $github->issue->body;
				$issue->comment			= ( (!empty($github->comment)) ? $github->comment : false );

				//echo '<pre>'; print_r($issue); die();
				
				$folders 	= json_decode($this->getFolders());
				$tasks		= json_decode($this->getTasks());
				$contacts	= json_decode($this->getContacts());
				$users		= ( (!empty($contacts->contacts) && !empty($contacts->contacts->list)) ? $contacts->contacts->list : array() );
				//echo '<pre>'; print_r($tasks); die();
				
				//create array of only user ids to include as sharedUsers
				//TODO: ability to share with specific users
				$user_ids		= array();
				$shared_users 	= '';
				foreach($users as $user) {
					$user_ids[] = $user->uid;
				}
				$shared_users = implode(',', $user_ids);
				
				
				//set folder and task id vars
				$folder_id 		= ( (empty($issue->milestone_title) ) ? 'none' : false );
				$wrike_task		= false;
				$task_id		= false;
				$parent_folder	= false;
				
				
				//check if folder (milestone) already exists in wrike
				if ( empty($folder_id) && !empty($folders->foldersTree) && !empty($folders->foldersTree->folders) ) {
					foreach( $folders->foldersTree->folders as $folder ) {
						if ( !empty( $folder->title ) && $folder->title == $issue->milestone_title ) {
							$folder_id 		= intval($folder->id);
							$parent_folder 	= $folder_id; 
							break;
						}
					} // end foreach
				} // end if !empty(folder)
				
				
				//check if task already exists in wrike
				if ( !empty($tasks->filteredList) && !empty($tasks->filteredList->list) ) {
					foreach( $tasks->filteredList->list as $task ) {
						if ( !empty($task->title) && $task->title == $issue->title ) {
							$wrike_task = $task;
							$task_id 	= $task->id;
							break;
						}
					} // end foreach
				} // end if !empty($tasks)
				
				
				
				//add folder (milestone) in wrike and get folder_id
				if ( empty($folder_id) ) { 
					$wrikeResponses['folderResponse']	= $this->addFolder($issue->milestone_title, $issue->milestone_id . '::' . $issue->milestone_num, $shared_users);
					$folderDecode 						= json_decode($wrikeResponses['folderResponse']); 
					if ( !empty($folderDecode->folder) && !empty($folderDecode->folder->id) ) {
						$folder_id 		= intval($folderDecode->folder->id);
						$parent_folder 	= $folder_id;
					} else if ( !empty($folderDecode->error) ) {
						error_log('Uh Oh!  Error Adding Folder: ' . $folderDecode->error->message);
						die();
					}
				}
				
				
				// sync task in wrike
				if ( empty($task_id) ) {
					$wrikeResponses['taskResponse']		= $this->addTask($issue->title, $issue->description, $issue->status, '1', false, false, false, $issue->assignee, $shared_users, $parent_folder);
					$taskDecode							= json_decode($wrikeResponses['taskResponse']);
					if ( !empty( $taskDecode->task ) && !empty( $taskDecode->task->id ) ) {
						$task_id = $taskDecode->task->id;
					} else if ( !empty($taskDecode->error) ) {
						error_log('Uh Oh!  Error Adding Task: ' . $taskDecode->error->message);
						die();
					}
				} else {
					//let's not overwrite anything that has changed in wrike since we use it for mapping out timelines, etc
					if ( empty($wrike_task->startDate) ) 	$wrike_task->startDate 	= false;
					if ( empty($wrike_task->dueDate) ) 		$wrike_task->dueDate 	= false;
					if ( empty($wrike_task->duration) ) 	$wrike_task->duration	= false;
					if ( empty($wrike_task->importance) ) 	$wrike_task->importance	= '1'; 
					if ( empty($wrike_task->parents) ) 		$wrike_task->parents	= false; 
					
					$wrike_task->responsibleUsers = (array) $wrike_task->responsibleUsers;
					$wrike_task->responsibleUsers =  ( ( empty($wrike_task->responsibleUsers) ) ? $issue->assignee : implode(',', $wrike_task->responsibleUsers) );

					$wrikeResponses['taskResponse']		= $this->updateTask($task_id, $issue->title, $issue->description, $issue->status, $wrike_task->importance, $wrike_task->startDate, $wrike_task->dueDate, $wrike_task->duration, $wrike_task->responsibleUsers, $shared_users, $parent_folder);
					$taskDecode							= json_decode($wrikeResponses['taskResponse']);
					if ( !empty($taskDecode->error) ) {
						error_log('Uh Oh!  Error Updating Task: ' . $taskDecode->error->message);
						die();
					}
				}
				
				
				//sync comments
				if ( !empty($issue->comment) ) {
					$wrikeResponses['commentResponse'] 	= $this->addComment($task_id, $issue->comment->body);
					$commentDecode						= json_decode($wrikeResponses['commentResponse']);
					if ( !empty($commentDecode->error) ) {
						error_log('Uh Oh!  Error Adding Comment: ' . $commentDecode->error->message);
						die();
					}
				}
				
				
			} // end if !empty($issue)
			
		} // end if ( !empty($github->action) )
		
		return $wrikeResponses;
	} //end github_sync 

} // end LN_WRIKE