var frida = require("frida");
var fs = require("fs");

function attach(replay_file) {
	frida.attach("WindowServer").then(function(sess) {
		var src = fs.readFileSync(process.cwd() + "/fuzz.js").toString();
		sess.createScript(src).then(function(script) {
			console.log("[+] injected fuzzer");
			// let's go 	
			script.message.connect(function(m, d) {
				// look for msg_replays coming back to log
				// and exceptions too
				console.log("MSG: ");
				console.log(JSON.stringify(m));
				if (m.payload.msgh_id) {
					// log for replay
					var data = JSON.stringify({
						msgh_bits: m.payload.msgh_bits,
						msgh_id: m.payload.msgh_id,
						msgh_buffer: d.toString("hex"),
						flip_offset: m.payload.flip_offset,
						flip_mask: m.payload.flip_mask
					});
					fs.appendFile("replay_log.txt", data + "\n", function(e) {
						if (e) {
							console.log("[!] replay logging not working, must exit");
							sess.detach();
						}
					}); // end appendfile cb
				} else {
					// only other thing we let through is exceptions
					fs.appendFile("crash_log.txt", JSON.stringify(m.payload, null, "\t") + "\n\n", function(e) {
						if (e) {
							console.log("[!] crash logging not working, must exit");
							sess.detach();
						}
					}); // end appendfile cb
				}
				//sess.detach(); // detach after first recv makes debug easier, keeps windowserver from crashing
			}); // end message handler
			script.load(); // w00t
			// if we are doing a replay run, send those to the agent
			if (replay_file) {
				// read them in
				var messages = JSON.parse("[" + fs.readFileSync(process.cwd() + "/" + process.argv[2]).toString().split("\n").join(",").slice(0, -1) + "]")
				script.post({
       		type: "replays",
					payload: {
						replays: messages
					}
      	}); // end replay msg post
			}
		});
		// keep it rolling	
		sess.detached.connect(function(reason, crash) {
			// we need to bring this whole show back up
			// windowserver will delay some, lame solution is to just wait until we think it will be there
			//return; // DISABLE DETACH FOR DEBUG
			console.log("[!] looks like windowserver went down, trying to reattach...");
			setTimeout(function() {
				attach();
			}, 5000); 
		}); // end detach handler
	}).catch(function(e) {
		console.log("[!] failed to reattach, will exit: " + e);
	}); // end frida attach handler
} // end attach

(process.argv[2]) ? attach(process.argv[2]) : attach();
