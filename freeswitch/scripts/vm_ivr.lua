freeswitch.consoleLog("info","In IVR LUA")

dest_num = session:getVariable("destination_number_ori");
session:answer()
session:execute("sched_hangup","+120 allotted_timeout");

if session:ready() then

        session:execute("playback","/usr/local/freeswitch/sounds/callnumber.wav");

        session:execute("say","en name_spelled iterated FEMININE ".. dest_num);

        session:execute("playback","/usr/local/freeswitch/sounds/afterbeep.wav");

        session:execute("sleep", "180000")
	-- os.execute("sleep 120")	
        session:execute("lua","vm_ivr.lua")

end
