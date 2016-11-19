<?php

class VirusTotalNotifications {
	private $root   = "https://virustotal.com/intelligence/";
	private $routes = array(
		"feed" => "hunting/notifications-feed/?key={{api_key}}&output=json",
		"next" => "hunting/notifications-feed/?key={{api_key}}&next={{next}}&output=json"
	);

	private $request;

	public function __construct() {
		$request = $this->parseRequest();
		if ($request) {
			$json = $this->getData($this->getURL($this->request));
			$this->view($json);
		}
	}

	private function parseRequest() {
		$this->request = [];
		if (isset($_POST['key']) && isset($_POST['action'])) {
			$this->request['key']    = $_POST['key'];
			$this->request['action'] = $_POST['action'];
			if(isset($_POST['next'])){
				$this->request['next'] = $_POST['next'];
			}
			return $this->request;
		} else {
			return false;
		}
	}

	private function getURL($request) {
		if (isset($this->routes[$request['action']])){
			$path = str_replace('{{api_key}}', $request['key'], $this->routes[$request['action']]);
		} else {
			$this->error();
		}
		

		if (isset($request['next'])){
			$path = str_replace('{{next}}', $request['next'], $path);
		}
		
		return $this->root . $path;
	}

	private function getData($url) {
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		$data  = curl_exec($ch);
		$error = curl_error($ch);
		return $data;
	}

	private function view($data) {
		if (!is_string($data)){
			$data = json_encode($data);
		}
		header('Content-type: application/json');
		echo $data;
		die();
	}

	private function error(){
		header("HTTP/1.0 500 Internal Server Error");
		$this->view(array('error' => true));
	}
}

$app = new VirusTotalNotifications();