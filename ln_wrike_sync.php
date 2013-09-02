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
    
require_once('ln_wrike_class.php');


//github sends issues as raw post data
$request = file_get_contents('php://input');


if ( !empty($request) ) {

	$payload 		= stripslashes($request);
	$secret			= 'Wrike oAuth Secret';
	$consumer 		= 'Wrike oAuth Key';
	$token			= 'Wrike Access Token';
	$token_secret	= 'Wrike Access Token Secret';
	$wrike 			= new LN_WRIKE($secret, $consumer, $token, $token_secret);
	
	$response = $wrike->github_sync($payload);
}