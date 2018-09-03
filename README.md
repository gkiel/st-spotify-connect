# st-spotify-connect

Quick app I threw together to be able to control which device Spotify is playing on via SmartThings

* Requires that you have a Spotify premium account.
* You'll need to create a client id through the Spotify developer portal: https://developer.spotify.com
* Once you've created that, you'll need to edit the settings and add https://graph.api.smartthings.com/oauth/callback as a Redirect URI
* In the app settings for the SmartThings app, you'll need to add two settings, clientId and clientSecret, which have the id and secret that come from the Spotify client id that you created

