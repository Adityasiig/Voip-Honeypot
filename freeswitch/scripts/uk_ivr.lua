freeswitch.consoleLog("info","In NEW IVR LUA");

session:execute("sched_hangup","+120 alotted_timeout");

session:answer()

for x  = 1,8 do

	-- random generating 
   	 no = math.random(1,8)
   	 print(value)
	
	if no == 1 then
		path = "/usr/local/freeswitch/sounds/UK/male.wav"
	elseif no == 2 then
		path = "/usr/local/freeswitch/sounds/UK/female2.wav"
	elseif no == 3 then
		path = "/usr/local/freeswitch/sounds/UK/female3.wav"
	elseif no == 4 then
		path = "/usr/local/freeswitch/sounds/UK/male4.wav"
	elseif no == 5 then
		path = "/usr/local/freeswitch/sounds/UK/female5.wav"
	elseif no == 6 then
		path = "/usr/local/freeswitch/sounds/UK/male6.wav"
	elseif no == 7 then
		path = "/usr/local/freeswitch/sounds/UK/female7.wav"
	elseif no == 8 then
		path = "/usr/local/freeswitch/sounds/UK/male8.wav"
	end

        session:execute("playback",path);

        session:execute("sleep", "9000");

        -- session:execute("lua","new_ivr.lua ".. no);
end