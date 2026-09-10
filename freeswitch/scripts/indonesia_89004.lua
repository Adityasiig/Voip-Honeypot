freeswitch.consoleLog("info"," [taiwan IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,6)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [taiwan IVR 89002] VALUE ".. value);

    if value == 1 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/1.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 2 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/2.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 3 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/3.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 4 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/4.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 5 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/5.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 6 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/indonesia_89004/6.wav");
		 session:execute("sleep", "30000")
    end

