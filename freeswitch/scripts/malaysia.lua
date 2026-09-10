freeswitch.consoleLog("info"," [Malaysia IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,14)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [Malaysia IVR] VALUE ".. value);

     if value == 1 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech1.wav");
		 end
     elseif value == 2 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech2.wav");
		 end
     elseif value == 3 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech3.wav");
		 end
	 elseif value == 4 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech4.wav");
		 end
     elseif value == 5 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech5.wav");
		end
     elseif value == 6 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech6.wav");
		end
	 elseif value == 7 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech7.wav");
		end
     elseif value == 8 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech8.wav");
		end
     elseif value == 9 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech9.wav");
		end
	 elseif value == 10 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech10.wav");
		end
     elseif value == 11 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech11.wav");
		end
     elseif value == 12 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech12.wav");
		 end
	 elseif value == 13 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech13.wav");
		end
     elseif value == 14 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/malaysia/speech14.wav");
		end
     end

