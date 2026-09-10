freeswitch.consoleLog("info"," [taiwan IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+7205 alotted_timeout");

     -- random generating 
     value = math.random(1,50)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [taiwan IVR 89002] VALUE ".. value);

    if value == 1 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/1.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 2 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/2.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 3 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/3.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 4 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/4.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 5 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/5.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 6 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/6.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 7 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/7.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 8 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/8.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 9 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/9.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 10 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/10.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 11 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/11.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 12 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/12.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 13 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/13.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 14 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/14.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 15 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/15.wav");
		 session:execute("sleep", "30000")

	elseif value == 16 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/16.wav");
		 session:execute("sleep", "30000")

	elseif value == 17 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/17fv.wav");
		 session:execute("sleep", "30000")
	elseif value == 18 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/18.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 19 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/19.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 20 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/20.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 21 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/21.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 22 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/22.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 23 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/23.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 24 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/24.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 25 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/25.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 26 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/26.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 27 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/27.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 28 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/28.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 29 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/29.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 30 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/30.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 31 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/31.wav");
		 session:execute("sleep", "30000")

	elseif value == 32 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/32.wav");
		 session:execute("sleep", "30000")

	elseif value == 33 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/33.wav");
		 session:execute("sleep", "30000")
	elseif value == 34 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/34.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 35 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/35.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 36 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/36.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 37 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/37.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 38 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/38.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 39 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/39.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 40 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/40.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 41 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/41.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 42 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/42.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 43 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/43.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 44 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/44.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 45 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/45.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 46 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/46.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 47 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/47.wav");
		 session:execute("sleep", "30000")

	elseif value == 48 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/48.wav");
		 session:execute("sleep", "30000")

	elseif value == 49 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/49.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 50 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/germany_89007/50.wav");
		  session:execute("sleep", "30000")
				 
    end

