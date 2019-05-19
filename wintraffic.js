var fs = require("fs");
var child = require("child_process");

function rand(mod) {
  return Math.floor(Math.random() * mod);
}

var apps = fs.readdirSync("/Applications").slice(2);

for (var i = 0; i < apps.length; i++) {
	apps[i] = "/Applications/" + apps[i] + "/Contents/MacOS/" + apps[i].replace(/.app/, "");
}

var app = apps[rand(apps.length)];
console.log("[i] chose app:", app);

var width = rand(8000);
var height = rand(6000); 
var x = rand(8000);
var y = rand(6000);

var script = `
set theApp to "${app.split("/")[app.split("/").length - 1]}"
set appHeight to ${width}
set appWidth to ${height}

tell application "Finder"
  set screenResolution to bounds of window of desktop
end tell

set screenWidth to item 3 of screenResolution
set screenHeight to item 4 of screenResolution

tell application theApp
  activate
  reopen
  set yAxis to (screenHeight - appHeight) / 2 as integer
  set xAxis to (screenWidth - appWidth) / 2 as integer
  set the bounds of the first window to {xAxis, yAxis, appWidth + xAxis, appHeight + yAxis}
end tell

tell application "System Events"
    set position of first window of process theApp to {${x}, ${y}}
end tell
EOF`;

console.log(script);

try {
	var proc = child.exec(app);
	var res = child.execSync("osascript <<EOF | echo " + script);
	setTimeout(function() {
		try {
			var res = child.execSync("killall '" + app.split("/")[app.split("/").length - 1] + "'");
		} catch(e) {
			process.exit();
		}
	}, 4000);
} catch(e) {
	console.log("[!] application did not launch", e);
}
