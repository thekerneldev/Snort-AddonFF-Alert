// =========================================================================================== //
// To import OS.File into your main.js code, add the following lines at the start of your 
// script (replacing TextEncoder with TextDecoder, both, or neither as needed):
// const {TextEncoder, OS, TextDecoder} = Cu.import("resource://gre/modules/osfile.jsm", {});

const {Cu,Cc,Ci} = require("chrome");
const {TextDecoder, OS} = Cu.import("resource://gre/modules/osfile.jsm", {});

var { ToggleButton } = require('sdk/ui/button/toggle');
var panels = require("sdk/panel");
//var fileIO = require("sdk/io/file");
var tabs = require("sdk/tabs");

var defaultSnortPathLog = "C:\\snort\\log"; //default snort log path

var cls = Cc['@mozilla.org/network/dns-service;1'];
var iface = Ci.nsIDNSService;
var dns = cls.getService(iface); //dns object

// =========================================================================================== //
//	Function to get hostname and translate hostname to IP address
// =========================================================================================== //

// Capture the URL after load
tabs.on('ready', function(tab){
tabs.on('load', function(tab){
	//console.log(tab.url);
	hostToIP(tab.url);
  });
});

function hostToIP(taburl){
	var url = require("sdk/url").URL(taburl);
		// console.log("HOST: " + url.host);
	var nsrecord = dns.resolve(url.host, true);
	
	while (nsrecord && nsrecord.hasMore()){
		ipAddress = (nsrecord.getNextAddrAsString());
		//console.log(ipAddress);
	}
	
	findDirectory(ipAddress); // Call function
}

// =========================================================================================== //
//	Load content of the log file
// =========================================================================================== //
function readTextFromFileLog(logFile) {

  var fileIO = require("sdk/io/file");
  var textLogFile = null;
  
  if (fileIO.exists(logFile)) {
    
	var TextReader = fileIO.open(logFile, "r");
	
    if (!TextReader.closed) {
      textLogFile = TextReader.read();	  
      TextReader.close();
    }
  }
  //console.log(" function readTextFromFileLog " + logFile);
  return textLogFile;
};

// =========================================================================================== //
//	Create button, panel and open/load the log file in the panel
// =========================================================================================== //
var button = ToggleButton({
  id: "button",
  label: "Intrusion Alert",
  icon: {"32": "./darkpig.png"
},
  //onChange: handleChange
});
 
// Insert information to panel
function infoPanel(logFile){

	var textLogFile = readTextFromFileLog(logFile);// Call function for capture text log / return log text
	//console.log(" function infoPanel " + textLogFile);
	
	// Panel configuration
 	var panel = panels.Panel({
	 contentURL: "data:text/html," + ("Attack: " + tabs.activeTab.title + textLogFile), // Show the content text log in panel
	 contentStyle: "body { border: 4px solid red; }",
	});
	panel.show({position: button});
	button.state(button, {"icon": "./pig.png",});

/*
	button.on("click", handleClick)
	function handleClick(state) {
		console.log("button '" + state.label + "' was clicked " + tabs.activeTab.url);
		hostToIP(tabs.activeTab.url);
		panel.show({position: button});
	}
*/  
}
// =========================================================================================== //		
// Iterate through the directory and find the directory log
// =========================================================================================== //
function findDirectory(ipAddress){
	let iterator = new OS.File.DirectoryIterator(defaultSnortPathLog); // Open iterator
	let subdirs = [];

// ## Recently code
var nsrecord = dns.resolve(dns.myHostName, 0);
var noIPv6 = 0;

console.log("hostname: " + dns.myHostName);

while (noIPv6 < 2){
	noIPv6++;
	console.log(noIPv6);
	nsrecord.getNextAddrAsString();
	if (noIPv6 == 1){
		myIP = (nsrecord.getNextAddrAsString());
		console.log("myIP: " + myIP);
	}
}
// ## End

// ## Incluir função para carregar arquivo com data mais atual. ##

	let promise = iterator.forEach(
	  function onEntry(entry) {
		//console.log(entry.path);
		if (entry.isDir && entry.name == ipAddress ) {
	       // if ((entry.isDir && entry.name == ipAddress ) || (entry.name == myIP))) {
			  //console.log("Yes, I find it!");
			  iterator.close(); // Close iterator
			  existPath(ipAddress); // Call function
		} else {
			  //console.log("I not find it!");
			  subdirs.push(entry); // get other path
		}
	  }
	);

// Close the iterator
promise.then(
  function onSuccess() {
	//console.log("Close the iterator: OK");
    iterator.close();
    return subdirs;
  },
  function onFailure(reason) {
	//console.log("Close the iterator: FAILURE");
    iterator.close();
    throw reason;
  }
);	
	
}

// =========================================================================================== //		
// Function list all logs files of the directory
// =========================================================================================== //
function existPath(ipAddress){
	//console.log("Finding path of IP address: " + ipAddress);
	let iterator2 = new OS.File.DirectoryIterator(defaultSnortPathLog + "\\" + ipAddress); // Open iterator
	let subdirs2 = [];

	let promise = iterator2.forEach(
	  function onEntry2(entry2) {
		console.log(entry2.path); // --
		logFile = (entry2.path);
		if (entry2.isDir) {
			subdirs2.push(entry2);
		} else {
			infoPanel(logFile); // Function for insert the file log information in the panel
			//iterator2.close();
		}
	}
	);

	// Close the iterator
	promise.then(
	  function onSuccess() {
		//console.log("Close the iterator2: OK");
		iterator2.close();
		return subdirs2;
	  },
	  function onFailure(reason) {
		//console.log("Close the iterator2: FAILURE " + reason);
		iterator2.close();
		throw reason;
	  }
	);

}
