freeswitch.consoleLog("info"," [indonasia IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,14)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [indonasia IVR] VALUE ".. value);

     if value == 1 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/indonasia/1.wav");
		 end
     elseif value == 2 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/indonasia/2.wav");
		 end
     elseif value == 3 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/indonasia/3.wav");
		 end
	 elseif value == 4 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/indonasia/4.wav");
		 end
     elseif value == 5 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/indonasia/5.wav");
		end
     elseif value == 6 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/indonasia/6.wav");
		end
	 elseif value == 7 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/indonasia/7.wav");
		end
     end

