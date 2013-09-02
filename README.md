github-wrike-sync
=================

Sync Github Issues && Milestones with Wrike Tasks and Folders using Github Service Hooks


- Clone this repo to your webserver.  Make sure it is accessible to the ourside world.

- Github service hooks only trigger upon pushes by default.  In order to set up triggers for issues you must send a post request to: https://api.github.com/repos/:owner/:repo/hooks with the following json payload:

{
  "name": "web",
  "active": true,
  "events": [
    "issues",
    "issue_comment"
  ],
  "config": {
    "url": "<Replace This With Your URL>",
    "content_type": "json"
  }
}

- In Github, go to "Settings" -> "Service Sooks" -> "WebHook URLs" and enter your publicly accessible URL.  Click Update.

- You should now be able to parse github issue / issue comment hooks. (create a test issue and check your logs)



Caveats
=======

- You must first replace the values in ln_wrike_sync.php with your own Wrike Credentials.  You can get more information by visiting: http://www.wrike.com/platform.jsp#auth

- Then enter each users github AND wrike ID's in the $github_user_ids array in ln_wrike_class.php

- Wrike does not currently support custom ID's when adding/updating/deleting via their API.  This makes it troublesome to accurately update existing tasks which have been previously synced.  Currently this script matches by Wrike title, but the real solution would be to store Wrike IDs in a local DB and match accordingly.  For now, if you do not edit any titles of you issues / milestones (tasks/folders) then you should be fine.  However keep in mind that the more your task list grows, the more performance will degrade.  Hopefully the fine fellows at Wrike will include a custom ID parameter which is indexed on their side in their upcoming v3 release of their API (fingers crossed).  In my opinion, it would only help them grow exponentially since it would make it that much easier for other users to integrate with Wrike!

- Currently all synced tasks are shared (not assigned) with all users in your Wrike account.  This may not be beneficial for some however for our small team it works just fine.  Users that were assigned an issue in Github will still be the responsibleUser in Wrike, but anyone else on the account can view it.



TODO
====

- Allow to easily share with select users instead of all
- provide logic for generating wrike access token / secret

