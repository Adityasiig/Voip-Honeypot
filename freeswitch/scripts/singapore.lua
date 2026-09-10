freeswitch.consoleLog("info"," [singapore New IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,49)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [singapore New IVR] VALUE ".. value);

     if value == 1 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/1.wav");
		 end
     elseif value == 2 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/2.wav");
		 end
     elseif value == 3 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/3.wav");
		 end
	 elseif value == 4 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/4.wav");
		 end
     elseif value == 5 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/5.wav");
		end
     elseif value == 6 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/6.wav");
		end
	 elseif value == 7 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/7.wav");
		end
     elseif value == 8 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/8.wav");
		end
     elseif value == 9 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/9.wav");
		end
	 elseif value == 10 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/10.wav");
		end
     elseif value == 11 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/11.wav");
		end
     elseif value == 12 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/12.wav");
		 end
	 elseif value == 13 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/13.wav");
		end
     elseif value == 14 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/14.wav");
		end
	elseif value == 15 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/15.wav");
		end
     elseif value == 16 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/16.wav");
		 end
	 elseif value == 17 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/17.wav");
		end
     elseif value == 18 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/18.wav");
		end
	elseif value == 19 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/19.wav");
		end
	elseif value == 20 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/20.wav");
		 end
     elseif value == 21 then
		 for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/21.wav");
		 end
	 elseif value == 22 then
	     for x=1,100 do
	      session:execute("playback","/usr/local/freeswitch/sounds/singapore/22.wav");
		 end
     elseif value == 23 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/23.wav");
		end
	elseif value == 24 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/24.wav");
		end
	elseif value == 25 then
		for x=1,100 do
	     session:execute("playback","/usr/local/freeswitch/sounds/singapore/25.wav");
		end
    end

