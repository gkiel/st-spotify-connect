/**
 *  Spotify Connect Device Handler
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
 
metadata {
	definition (name: "Spotify Connect Device", namespace: "gkiel", author: "Garrett Kiel") {
		capability "Switch"
        capability "Actuator"
	}


	simulator {
		// TODO: define status and reply messages here
	}

	tiles {
		//standardTile("actionRings", "device.switch", width: 2, height: 2, canChangeIcon: true) {
        //    state "off", label: '${currentValue}', action: "switch.on",
        //          icon: "st.switches.switch.off", backgroundColor: "#ffffff"
        //    state "on", label: '${currentValue}', action: "switch.off",
        //          icon: "st.switches.switch.on", backgroundColor: "#00a0dc"
        //}
        
        multiAttributeTile(name:"rich-control", type: "lighting", canChangeIcon: true){
            tileAttribute ("device.switch", key: "PRIMARY_CONTROL") {
                 attributeState "on", label:'${name}', action:"switch.off", icon:"st.switches.switch.off", backgroundColor:"#00A0DC", nextState:"turningOff"
                 attributeState "off", label:'${name}', action:"switch.on", icon:"st.switches.switch.on", backgroundColor:"#ffffff", nextState:"turningOn"
 			}
        }
        
        // the "switch" tile will appear in the Things view
        main("switch")
        
        details("rich-control")
	}
}

// parse events into attributes
def parse(String description) {
	log.info "Parsing '${description}'"
	// TODO: handle 'switch' attribute

}

// handle commands
def on() {
	def deviceId = device.deviceNetworkId
    log.info("Tranferring playback to ${deviceId}")
    def reqBody = [
    	device_ids: [deviceId],
        play: true
    ]
    def url = "https://api.spotify.com/v1/me/player"
	def reqParams = [
    	uri: url,
        headers: parent.getRequestHeaders(),
        body: reqBody
    ]
    
    try {
        asynchttp_v1.put(processOnResponse, reqParams)
    } catch (e) {
    	log.error("Error: ${e.getCause()}")
    }
}

def processOnResponse(response, data) {
	if (response.hasError()) {
    	log.error("Error transferring playback to ${device.label}: ${response.errorMessage}")
    } else {
    	sendEvent(name: "switch", value: "on")
    	parent.turnOffOthers(device.deviceNetworkId)
    }
}

def off() {
	log.info "Executing 'off'"
	// TODO: handle 'off' command
    def url = "https://api.spotify.com/v1/me/player/pause"
    def reqHeaders = parent.getRequestHeaders()
    reqHeaders.put("Content-Length", "0")
    def reqParams = [
    	uri: url,
        headers: reqHeaders,
        body: reqBody
    ]
    try {
        asynchttp_v1.put(processOffResponse, reqParams)
    } catch (e) {
    	log.error("Error: ${e.getCause()}")
    }
    sendEvent(name: "switch", value: "off")
}

def processOffResponse(response, data) {
	if (response.hasError()) {
    	log.error("Error stopping playback on ${device.label}: ${response.errorMessage}")
    } else {
        sendEvent(name: "switch", value: "off")
    }
}