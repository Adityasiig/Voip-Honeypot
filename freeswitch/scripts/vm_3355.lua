freeswitch.consoleLog("info","In IVR LUA")

dest_num = session:getVariable("destination_number_ori");
session:answer()
----session:execute("sched_hangup","+120 allotted_timeout");

if session:ready() then
	session:execute("set","playback_timeout_sec=120");
        session:execute("playback","/usr/local/freeswitch/sounds/Voicemail_3355.wav");


        session:execute("sleep", "30000")
	-- os.execute("sleep 120")	
	session:hangup()
end
