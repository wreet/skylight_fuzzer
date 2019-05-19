// try for chance to handle exceptions ourselves
Process.setExceptionHandler(function(e) {
	console.log("[i] instruction info");
	console.log(Instruction.parse(e.context.rip));
	console.log(JSON.stringify(Instruction.parse(e.context.rip)));
	console.log("[i] exception info");
	console.log(e);
	send({
		exception: e,
		instruction: Instruction.parse(e.context.rip)
	});
	Thread.sleep(1);
	return false; // tell program we did not handle the exception
});

var ignore_list = [ // some msgh_id are the same boring crashes over and over
	"0x73a8", // _XSetConnectionNotifyInterests
	"0x73a7", // _XSetProcessNotifyInterests
	"0x7290", // _XDisplayVisualBell
//	"0x7308", // _XSetKeyTranslationTable
//	"0x7290", // xdisplalyvisualbell
//	"0x7350", // _XSetMenuBars
//	"0x7372",
//	"0x7373",
//	"0x73b8",
//	"0x734b",
//	"0x7230",
//	"0x73b6", //_XSetPressureConfigurationOverride
//	"0x74a3", // _XRegisterColorSpace
//	"0x73a4", // _XReassociateWindowsSpacesByGeometry
//	"0x734e", // _XRegisterCursorImages
//	"0x722a", // _XSetWindowOpaqueShape
//	"0x7318", // _XShapeWindow
//	"0x731b", // _XContextDidCommit
//	"0x7337", // _XPackagesEnableConnectionOcclusionNotifications 
//	"0x73b7", // _XAddStructuralRegionOfType
//	"0x72d7", // _XSetConnectionProperty
//	"0x73b9", // _XStructuralRegionSetShape
//	"0x7372", // _XCopySpacesForWindows
//	"0x73c0", // _XTrackingRegionSetForceConfig
//	"0x7307", // _XSetWindowEventShape
//	"0x7263", // _XFlushRegion
//	"0x7242", // _XSetWindowProperty
//	"0x7330", // _XContextDidCommit
//	"0x722c", // _XSetWindowCornerMask
//	"0x7229", // _XWindowSetShadowProperties
];

var REPLAY_MODE = false;
var replays = {};
// setup replay ability
recv("replays", function onMessage(msg) {
	console.log("[+] replay mode");
	var replay_list = msg.payload.replays;
	for (var i = 0; i < replay_list.length; i++) {
		if (!replays[replay_list[i].msgh_id]) replays[replay_list[i].msgh_id] = [];
		replays[replay_list[i].msgh_id].push(replay_list[i]);
	}
	REPLAY_MODE = true;
	console.log("[i] replays ready");
});

function Msg() {
	this.msgh_bits = "";
	this.msgh_id = "";
	this.msgh_buff = "";
	this.flip_offset = 0;
	this.flip_mask = 0;

	this.log = function() {
		send({
			msgh_bits: this.msgh_bits,
			msgh_id: this.msgh_id,
			flip_offset: this.flip_offset,
			flip_mask: this.flip_mask
		}, this.msgh_buff); // frida wants data like this passed as second arg
	};
}

function rand(mod) {
	return Math.floor(Math.random() * mod);
}

function InstallProbe(probe_address, target_register) {
    var probe = Interceptor.attach(probe_address, function(args) {
        var input_msg  = args[0]; // rdi (the incoming mach_msg)
        var output_msg = args[1]; // rsi (the response mach_msg)
				var complex = false;    

        // extract the call target & its symbol name (_X...)
        var call_target = this.context[target_register];
        var call_target_name = DebugSymbol.fromAddress(call_target);
        
        // let's go
        console.log('[+] Message received for ' + call_target_name);

				// work with it
				console.log("msg in(rdi): " + args[0]);
				
				// msgh_bits is unsigned int, offset: dec 0
				var msgh_bits = args[0].readU32().toString(16);
				console.log("msgh_bits: 0x" + msgh_bits);
				// is it complex
				if ((parseInt(msgh_bits, 16) & 0x80000000) != 0) {
					console.log("[i] handling complex message");
					complex = true;
					return; // DEBUG 
				}
			
				// msgh_size is unsigned int, offset: dec 4
				var msgh_size = args[0].add(4).readU32();//.toString(16);
				console.log("msgh_size: 0x" + msgh_size.toString(16));	
		
				// msgh_remote_port is unsigned int, offset: dec 8
				var msgh_remote_port = args[0].add(8).readU32();
				console.log("msgh_remote_port: " + msgh_remote_port);
	
				// msgh_local_port is unsigned int, offset: dec 12
				var msgh_local_port = args[0].add(12).readU32();
				console.log("msgh_local_port: " + msgh_local_port);

				// msgh_voucher_port is unsigned int, offset: dec 16
				var msgh_voucher_port = args[0].add(16).readU32();
				console.log("msgh_voucher_port: " + msgh_voucher_port);

				// msgh_id is signed int, offset: dec 20
				var msgh_id = args[0].add(20).readS32().toString(16);
				if (ignore_list.indexOf("0x" + msgh_id) > -1 && !REPLAY_MODE) return; // either boring or we already have some crashes	
				console.log("msgh_id: 0x" + msgh_id);

				if (complex) {
					// 24 will be our descriptor count
					var msgh_descriptor_count = args[0].add(24).readU32();
					console.log("msgh_descriptor_count: " + msgh_descriptor_count);
				}

				// msgh_buffer is data of size msgh_size - 24, offset: dec 24
				var buff_pos = 24;
				if (complex) {
					buff_pos += 4;
				}
				var msgh_buff = args[0].add(buff_pos).readByteArray(msgh_size - buff_pos);
	
				if (msgh_buff.byteLength == 0) {
					console.log("[i] zero len trailing buffer??");
					return;
				}			
				console.log("msgh_buffer: ");
				console.log(msgh_buff);
				
				if (REPLAY_MODE) {
					if (replays["0x" + msgh_id] && replays["0x" + msgh_id].length > 0) {
						r = replays["0x" + msgh_id][rand(replays["0x" + msgh_id].length)];
						console.log("[i] chose replay:: ");
						console.log(JSON.stringify(r));
						// setup flip mask and offset
						var flip_offset = r.flip_offset;
						var flip_mask = r.flip_mask; 
					} else {
						return; // don't modify new messages in replay mode
					}
				} else {
					// flip some bits in msgh_buff, and write res to memory
					// since we are not replaying we setup fresh flips
					var flip_offset = rand(msgh_buff.byteLength)
					if (complex && flip_offset < 8) flip_offset += 8;
					console.log("offset: 0x" + flip_offset.toString(16));
					var flip_mask = rand(256);
					console.log("flip mask: " + flip_mask);
				}
				try {	
					var v = new DataView(msgh_buff, flip_offset, 1);
				} catch(e) {
					// usually happens if original flip offset longer than this messgae
					// only an issue in replay mode, we'll skip
					return;
				}
				v.setInt8(0, (v.getInt8() ^ flip_mask));
				console.log(msgh_buff);
				// log for replay
				var m = new Msg();
				m.msgh_bits = "0x" + msgh_bits;
				m.msgh_id = "0x" + msgh_id;
				m.msgh_buff = msgh_buff;
				m.flip_offset = flip_offset;
				m.flip_mask = flip_mask;
				m.log();
				// write the fuzzed buff
				args[0].add(buff_pos).writeByteArray(msgh_buff);	
    });
    return probe;
} // end installprobe

function intercept() {
	var targets = [
		['0xcde66', 'rax'],  // WindowServer_subsystem || hook before call since frida needs 5 bytes before basic block end
		['0x27d4a', 'rcx'],  // Renezvous_subsystem
		['0xd0886', 'rax']   // Services_subsystem
	];

	// locate the runtime address of the SkyLight framework
	var skylight = Module.findBaseAddress('SkyLight');
	console.log('[*]  SkyLight @ ' + skylight);

	// hook the target instructions
	for (var i in targets) {
 	   var hook_address = ptr(skylight).add(targets[i][0]); // base + offset
 	   InstallProbe(hook_address, targets[i][1])
 	   console.log('[+] Hooked dispatch @ ' + hook_address);
	}
}

intercept();
