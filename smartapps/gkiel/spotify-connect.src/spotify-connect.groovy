/**
 *  Spotify Connect
 *
 *  Copyright 2018 Garrett Kiel
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */
include 'asynchttp_v1'
 
definition(
    name: "Spotify Connect",
    namespace: "gkiel",
    author: "Garrett Kiel",
    description: "Control which device Spotify plays on",
    category: "Convenience",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png"
) {
	appSetting "clientId"
    appSetting "clientSecret"
}


preferences {
	page(name: "Credentials", title: "Sample Authentication", content: "authPage", nextPage: "chooseDevices", install: false)
	page(name: "auth")
    page(name: "chooseDevices")
    section("Title") {
		// TODO: put inputs here
	}
}

mappings {
    path("/oauth/initialize") {action: [GET: "oauthInitUrl"]}
    path("/oauth/callback") {action: [GET: "callback"]}
}

def getRequestHeaders() {
    def headers = [
    	Authorization: "Bearer " + state.authToken
    ]
    return headers
}

def chooseDevices(params) {
	def reqParams = [
    	uri: "https://api.spotify.com/v1/me/player/devices",
        headers: getRequestHeaders()
    ]
    def addedDevices = [:]
    def newDevices = [:]
    httpGet(reqParams) { resp ->
        def devices = resp.data.devices
        devices.each {
            def devId = it.id

            def d = getChildDevice(devId)
            if (d) {
                addedDevices.put(devId, it)
            } else {
                newDevices.put(devId, it)
            }
        }
    }
    
    if (params.add) {
    	log.info("adding ${params.add}")
        def devId = params.add
        def dev = newDevices.get(params.add)
        def d = addChildDevice("gkiel", "Spotify Connect Device", devId, null, ["label": dev.name])
        newDevices.remove(devId)
        addedDevices.put(devId, dev)
        if (dev.is_active) {
        	d.sendEvent(name: "switch", value: "on")
        } else {
        	d.sendEvent(name: "switch", value: "off")
        }
    }
    
    if (params.remove) {
    	log.info("removing ${params.remove}")
        def devId = params.remove
        def dev = addedDevices.get(devId)
        deleteChildDevice(devId)
        addedDevices.remove(devId)
        newDevices.put(devId, dev)
    }
    
    dynamicPage(name:"chooseDevices", title: "Device List") {
    	section("Added Devices") {
			addedDevices.sort{it.value.name}.each { 
				def devId = it.key
				def name = it.value.name
				href(name:"${devId}", page:"chooseDevices", description:"", title:"Remove ${name}", params: [remove: devId], submitOnChange: true )
			}
		}
        section("Available Devices") {
			newDevices.sort{it.value.name}.each { 
				def devId = it.key
				def name = it.value.name
				href(name:"${devId}", page:"chooseDevices", description:"", title:"Add ${name}", params: [add: devId], submitOnChange: true )
			}
        }
    }
}

def authPage() {
    // Check to see if SmartApp has its own access token and create one if not.
    if(!state.accessToken) {
        // the createAccessToken() method will store the access token in state.accessToken
        createAccessToken()
    }

    def redirectUrl = "https://graph.api.smartthings.com/oauth/initialize?appId=${app.id}&access_token=${state.accessToken}&apiServerUrl=${getApiServerUrl()}"
    // Check to see if SmartThings already has an access token from the third-party service.
    if(!state.authToken) {
        return dynamicPage(name: "auth", title: "Login", nextPage: "", uninstall: false) {
            section() {
                paragraph "Tap below to log in to Spotify and authorize SmartThings access"
                href url: redirectUrl, style: "embedded", required: true, title: "Spotify", description: "Click to enter credentials"
            }
        }
    } else {
        // SmartThings has the token, so we can just call the third-party service to list our devices and select one to install.
        refreshApiToken()
   		initialize()
        return dynamicPage(name: "auth", title: "Login", nextPage: "chooseDevices", install: false, uninstall: true) {
            section() {
                paragraph "Tap next to select your devices"
            }
        }
    }
}

def oauthInitUrl() {

    // Generate a random ID to use as a our state value. This value will be used to verify the response we get back from the third-party service.
    state.oauthInitState = UUID.randomUUID().toString()

    def oauthParams = [
        response_type: "code",
        scope: "user-modify-playback-state user-read-playback-state",
        client_id: appSettings.clientId,
        client_secret: appSettings.clientSecret,
        state: state.oauthInitState,
        redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
    ]
    
    def apiEndpoint = "https://accounts.spotify.com"

    redirect(location: "${apiEndpoint}/authorize?${toQueryString(oauthParams)}")
}

// The toQueryString implementation simply gathers everything in the passed in map and converts them to a string joined with the "&" character.
String toQueryString(Map m) {
        return m.collect { k, v -> "${k}=${URLEncoder.encode(v.toString())}" }.sort().join("&")
}

def callback() {
    log.debug "callback()>> params: $params, params.code ${params.code}"

    def code = params.code
    def oauthState = params.state

    // Validate the response from the third party by making sure oauthState == state.oauthInitState as expected
    if (oauthState == state.oauthInitState){
        def tokenParams = [
            grant_type: "authorization_code",
            code      : code,
            client_id : appSettings.clientId,
            client_secret: appSettings.clientSecret,
            redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
        ]

        // This URL will be defined by the third party in their API documentation
        def tokenUrl = "https://accounts.spotify.com/api/token"

        httpPost(uri: tokenUrl, body: tokenParams) { resp ->
            state.refreshToken = resp.data.refresh_token
            state.authToken = resp.data.access_token
            state.authTokenExpiresIn = resp.data.expires_in
        }
        log.info("Auth token expires in: " + state.authTokenExpiresIn)

        if (state.authToken) {
            // call some method that will render the successfully connected message
            success()
        } else {
            // gracefully handle failures
            fail()
        }

    } else {
        log.error "callback() failed. Validation of state did not match. oauthState != state.oauthInitState"
    }
}

// Example success method
def success() {
    def message = """
                <p>Your account is now connected to SmartThings!</p>
                <p>Click 'Done' to finish setup.</p>
                """
    displayMessageAsHtml(message)
}

def refreshApiToken() {
	log.info("Refreshing api token")
	def tokenParams = [
        grant_type: "refresh_token",
        refresh_token: state.refreshToken
    ]
    
    def authString = appSettings.clientId + ":" + appSettings.clientSecret
    def encodedAuth = authString.bytes.encodeBase64()
    def headers = [
    	"Authorization": "Basic " + encodedAuth
    ]

    // This URL will be defined by the third party in their API documentation
    def tokenUrl = "https://accounts.spotify.com/api/token"
    
    def reqParams = [
    	uri: tokenUrl,
        body: tokenParams,
        headers: headers
    ]

	try {
        httpPost(reqParams) { resp ->
            state.authToken = resp.data.access_token
            state.authTokenExpiresIn = resp.data.expires_in
        }
    } catch (e) {
    	log.info("Something went wrong: ${e}");
    }
}

// Example fail method
def fail() {
    def message = """
        <p>There was an error connecting your account with SmartThings</p>
        <p>Please try again.</p>
    """
    displayMessageAsHtml(message)
}

def displayMessageAsHtml(message) {
    def html = """
        <!DOCTYPE html>
        <html>
            <head>
            </head>
            <body>
                <div>
                    ${message}
                </div>
            </body>
        </html>
    """
    render contentType: 'text/html', data: html
}

def installed() {
	log.debug "Installed with settings: ${settings}"

	initialize()
}

def updated() {
	log.debug "Updated with settings: ${settings}"

	unsubscribe()
	initialize()
}

def initialize() {
	// TODO: subscribe to attributes, devices, locations, etc.
    log.info("initialize called")
    // The expires_in always appears to be 3600 seconds
    runEvery1Hour(refreshApiToken)
    runEvery15Minutes(pollForCurrentActiveDevice)
}

def uninstalled() {
	log.info("uninstall called")
    revokeAccessToken()
    getAllChildDevices().each {
    	log.info("Removing ${it.label}")
    	deleteChildDevice(it.deviceNetworkId)
    }
}

/**
 * Devices like phones will only show up in the device list api when spotify
 * is actively playing. This will make sure that snartthings will show the
 * correct device is active after a while
 */
def pollForCurrentActiveDevice() {
	log.info("Getting active device")
	def url = "https://api.spotify.com/v1/me/player"
    def reqHeaders = getRequestHeaders()
    reqHeaders.put("Content-Length", "0")
    def reqParams = [
    	uri: url,
        headers: reqHeaders
    ]
    
    try {
    	log.info("Making request")
    	asynchttp_v1.get(processActiveDeviceResponse, reqParams)
    } catch (e) {
    	log.error("Error getting current device: ${e}")
    }
}

def processActiveDeviceResponse(resp, data) {
	if (resp.hasError()) {
    	log.error("Error getting active device: ${resp.errorMessage}")
    } else {
        def jsonResp = resp.json
        def activeId = jsonResp.device.id
        log.info("Active device is ${jsonResp.device.name}, is_active = ${jsonResp.device.is_active}")
        def device = getChildDevice(activeId)
        log.info("Current state: ${device.currentState('switch').value}, is_playing = ${jsonResp.is_playing}")
        if (device.currentState('switch').value.equals("off") && jsonResp.is_playing) {
        	log.info("Turning on ${jsonResp.device.name}")
            device.sendEvent(name: "switch", value: "on")
            turnOffOthers(activeId)
        } else {
        	log.info("Not turning on ${jsonResp.device.name}")
        }
    }
}

/**
 * Only one spotify device can be active at a time, so when we turn on one,
 * we need to turn off the rest of them
 */
def turnOffOthers(deviceId) {
    getAllChildDevices().each {
        if (it.deviceNetworkId != deviceId) {
            it.sendEvent(name: "switch", value: "off")
        }
    }
}

// TODO: implement event handlers