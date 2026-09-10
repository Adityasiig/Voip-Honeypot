freeswitch.consoleLog("info"," [China New IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,19)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [China New IVR] VALUE ".. value);

     if value == 1 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech1.wav");
		 end
     elseif value == 2 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech2.wav");
		 end
     elseif value == 3 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech3.wav");
		 end
	 elseif value == 4 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech4.wav");
		 end
     elseif value == 5 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech5.wav");
		end
     elseif value == 6 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech6.wav");
		end
	 elseif value == 7 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech7.wav");
		end
     elseif value == 8 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech8.wav");
		end
     elseif value == 9 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech9.wav");
		end
	 elseif value == 10 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech10.wav");
		end
     elseif value == 11 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech11.wav");
		end
     elseif value == 12 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech12.wav");
		 end
	 elseif value == 13 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech13.wav");
		end
     elseif value == 14 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech14.wav");
		end
	elseif value == 15 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech15.wav");
		end
     elseif value == 16 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech16.wav");
		 end
	 elseif value == 17 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech17.wav");
		end
     elseif value == 18 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech18.wav");
		end
	elseif value == 19 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/china_new/speech19.wav");
		end
     end

