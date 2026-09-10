freeswitch.consoleLog("info"," [UK2 New IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,49)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [UK2 New IVR] VALUE ".. value);

     if value == 1 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech1.wav");
		 end
     elseif value == 2 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech2.wav");
		 end
     elseif value == 3 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech3.wav");
		 end
	 elseif value == 4 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech4.wav");
		 end
     elseif value == 5 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech5.wav");
		end
     elseif value == 6 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech6.wav");
		end
	 elseif value == 7 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech7.wav");
		end
     elseif value == 8 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech8.wav");
		end
     elseif value == 9 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech9.wav");
		end
	 elseif value == 10 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech10.wav");
		end
     elseif value == 11 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech11.wav");
		end
     elseif value == 12 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech12.wav");
		 end
	 elseif value == 13 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech13.wav");
		end
     elseif value == 14 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech14.wav");
		end
	elseif value == 15 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech15.wav");
		end
     elseif value == 16 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech16.wav");
		 end
	 elseif value == 17 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech17.wav");
		end
     elseif value == 18 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech18.wav");
		end
	elseif value == 19 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech19.wav");
		end
	elseif value == 20 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech20.wav");
		 end
     elseif value == 21 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech21.wav");
		 end
	 elseif value == 22 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech22.wav");
		 end
     elseif value == 23 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech23.wav");
		end
     elseif value == 24 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech24.wav");
		end
	 elseif value == 25 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech25.wav");
		end
     elseif value == 26 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech26.wav");
		end
     elseif value == 27 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech27.wav");
		end
	 elseif value == 28 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech28.wav");
		end
     elseif value == 29 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech29.wav");
		end
     elseif value == 30 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech30.wav");
		 end
	 elseif value == 31 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech31.wav");
		end
     elseif value == 32 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech32.wav");
		end
	elseif value == 33 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech33.wav");
		end
     elseif value == 34 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech34.wav");
		 end
	 elseif value == 35 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech35.wav");
		end
     elseif value == 36 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech36.wav");
		end
	elseif value == 37 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech37.wav");
		end
	elseif value == 38 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech38.wav");
		end
     elseif value == 39 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech39.wav");
		end
     elseif value == 40 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech40.wav");
		 end
	 elseif value == 41 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech41.wav");
		end
     elseif value == 42 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech42.wav");
		end
	elseif value == 43 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech43.wav");
		end
     elseif value == 44 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech44.wav");
		 end
	 elseif value == 45 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech45.wav");
		end
     elseif value == 46 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech46.wav");
		end
	elseif value == 47 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech47.wav");
		end
	elseif value == 48 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech48.wav");
		end
	elseif value == 49 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/UK2/speech49.wav");
		end
     end

