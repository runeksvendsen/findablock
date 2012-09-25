window.block_header = [];
window.hash_clock = 0;
window.rate_clock = 0;
window.block_data = [];
window.nonce = 0;
window.bigIntSmHash = str2bigInt("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","16",0);
window.bigIntTarget = "";
window.lasttime = 0;
window.lastnonce = 0;

jQuery(document).ready(function() {
    $("#block_hash").val("");

    $("#doit").click(function() {
        start_hashing();
    });

    $("#testbtn").click(function () {
        settext();
        $("#block_data").html(window.block_header);
    });

    $("#getblockdata").click(function () {
        //$("#block_data").html("Loading block data...");
        get_block_data();
    });
});

function set_block_data() {
    //$("#block_data").html(JSON.stringify(block_data, null, 4));

    $("#version").val(block_data["ver"]);
    $("#prev_hash").val(block_data["prev_block"]);
    $("#merkle_root").val(block_data["mrkl_root"]);
    $("#human_time").html(String(new Date(block_data["time"]*1000)));
    $("#timestamp").val(switch_endian(block_data["time"].toString(16)));
    $("#target").val(switch_endian(block_data["bits"]));
    $("#nonce").val(0);
    $("#target_hash").val(zero_pad(compact_to_full(switch_endian(block_data["bits"])), 64));
}

function get_block_data() {
    jQuery.ajax({
        url: '/request',
        type: "POST",
        data: {request : "getblock", address : $("#recv_addr").val()},
        success: function(data) {
            if (data == "error: couldn't connect to server") {
                alert(data);
                return false;
            }
            block_data = data;
            set_block_data()
        },
        });
    return false;
}

function switch_endian(hex) {
    if (hex.length % 2 != 0) {
        return -1
    }

    var result = ""
    var start = (hex.length-2)
    while (start >= 0) {
        result += hex.substring(start, start+2)
        start -= 2
    }
    return result;
}

function compact_to_full(compact)
{
	bigendian = switch_endian(compact);
	
	length = parseInt(bigendian.substring(0,2), 16);
	
	full = bigendian.substring(2,8)
	while (full.length < length*2) {
		full = full + "00"
	}
	
	return full
}

function zero_pad(string, num_zero) {
	pad = Array(num_zero+1).join("0")
	return (pad.slice(string.length, pad.length) + string);
}

function u32_lehex(number) {
    pad = "00000000";
    hex = parseInt(number).toString(16)
    padded = pad.slice(hex.length, pad.length) + hex;

    return switch_endian(padded);
}

function load_values() {
    header_data = CryptoJS.enc.Hex.parse(
        u32_lehex($("#version").val()) + switch_endian($("#prev_hash").val()) + 
        switch_endian($("#merkle_root").val()) + $("#timestamp").val() + 
        $("#target").val() + u32_lehex($("#nonce").val()));
        
	window.nonce = $("#nonce").val();
	window.bigIntTarget = str2bigInt(compact_to_full($("#target").val()),"16",0);

    window.block_header = CryptoJS.enc.Hex.stringify(header_data);
}

function dsha256(data) {
    return CryptoJS.SHA256(CryptoJS.SHA256(data));
}
  

function settext() {
    load_values();

    var hash = dsha256(CryptoJS.enc.Hex.parse(window.block_header));

    var littleEndian = switch_endian(hash.toString(CryptoJS.enc.Hex));

    $("#block_hash").val(littleEndian);

    var bigIntHash = str2bigInt(littleEndian,"16",0);

    if ( !equals(bigIntHash, window.bigIntSmHash) && !greater(bigIntHash, window.bigIntSmHash) ) {
        window.bigIntSmHash = bigIntHash;
        $("#sm_hash").val(littleEndian);
    }
    
    if ( !equals(bigIntHash, bigIntTarget) && !greater(bigIntHash, bigIntTarget) ) {
        $("#success").html("<blink>SUCCESS!! You've found a block!</blink>");
        window.hash_clock=window.clearInterval(window.hash_clock);
		window.rate_clock=window.clearInterval(window.rate_clock);
		return true;
    }
	return false;
}

function hash_iter() {
    window.nonce++;
    jQuery("#nonce").val(window.nonce);
    settext();
}

function start_hashing() {
	$("#success").html("");
    if (settext() == true) {
    	return;
    }
    $("#sm_hash").val($("#block_hash").val());
    window.lasttime = new Date().getTime();
    window.lastnonce = window.nonce;
    rate_clock = setInterval(rate_measure, 1000);
    hash_clock = setInterval(hash_iter,1);
}

function rate_measure() {
    thistime = new Date().getTime();
    speed = Math.round((window.nonce-window.lastnonce)/(thistime-window.lasttime)*1000);
    window.lasttime = thistime;
    window.lastnonce = window.nonce
    jQuery("#hash_rate").html(speed + " hashes/sec");
}
