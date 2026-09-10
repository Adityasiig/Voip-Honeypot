freeswitch.consoleLog("info"," [vietnam IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+7205 alotted_timeout");

     -- random generating 
     value = math.random(1,36)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [vietnam IVR 89002] VALUE ".. value);

    if value == 1 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/1.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 2 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/2.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 3 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/3.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 4 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/4.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 5 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/5.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 6 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/6.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 7 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/7.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 8 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/8.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 9 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/9.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 10 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/10.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 11 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/11.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 12 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/12.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 13 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/13.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 14 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/14.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 15 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/15.wav");
		 session:execute("sleep", "30000")

	elseif value == 16 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/16.wav");
		 session:execute("sleep", "30000")

	elseif value == 17 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/17fv.wav");
		 session:execute("sleep", "30000")
	elseif value == 18 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/18.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 19 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/19.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 20 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/20.wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 21 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/21.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 22 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/22.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 23 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/23.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 24 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/24.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 25 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/25.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 26 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/26.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 27 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/27.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 28 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/28.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 29 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/29.wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 30 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/30.wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 31 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/31.wav");
		 session:execute("sleep", "30000")

	elseif value == 32 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/32.wav");
		 session:execute("sleep", "30000")

	elseif value == 33 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/33.wav");
		 session:execute("sleep", "30000")
	elseif value == 34 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/34.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 35 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/35.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 36 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/36.wav");
		  session:execute("sleep", "30000")
	elseif value == 37 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/37.wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 38 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/38.wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 39 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/39.wav");
		  session:execute("sleep", "30000")
	elseif value == 40 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/thailand_89005/40.wav");
		  session:execute("sleep", "30000")
		 
    end