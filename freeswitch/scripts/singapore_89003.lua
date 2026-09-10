freeswitch.consoleLog("info"," [taiwan IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
math.random(); math.random(); math.random() -- warming up

session:execute("sched_hangup", "+6300 alotted_timeout");

     -- random generating 
     value = math.random(1,47)
     print(value)

     session:answer();
	 freeswitch.consoleLog("info"," [taiwan IVR 89002] VALUE ".. value);

    if value == 1 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(1).wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 2 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(2).wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 3 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(3).wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 4 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(4).wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 5 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(5).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 6 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(6).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 7 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(7).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 8 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(8).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 9 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(9).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 10 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(10).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 11 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(11).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 12 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(12).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 13 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(13).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 14 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(14).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 15 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(15).wav");
		 session:execute("sleep", "30000")

	elseif value == 16 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(16).wav");
		 session:execute("sleep", "30000")

	elseif value == 17 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(17).wav");
		 session:execute("sleep", "30000")
	elseif value == 18 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(18).wav");
		 session:execute("sleep", "30000")
	elseif value == 19 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(19).wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 20 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(20).wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 21 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(21).wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 22 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(22).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 23 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(23).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 24 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(24).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 25 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(25).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 26 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(26).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 27 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(27).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 28 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(28).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 29 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(29).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 30 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(30).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 31 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(31).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 32 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(32).wav");
		 session:execute("sleep", "30000")

	elseif value == 33 then
		
		 session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(33).wav");
		 session:execute("sleep", "30000")

	elseif value == 34 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(34).wav");
		 session:execute("sleep", "30000")
	elseif value == 35 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(35).wav");
		 session:execute("sleep", "30000")
	elseif value == 36 then
		 
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(36).wav");
		  session:execute("sleep", "30000")
				 
    elseif value == 37 then
		
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(37).wav");
		  session:execute("sleep", "30000")
		 
	elseif value == 38 then
	     
	      session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(38).wav");
		  session:execute("sleep", "30000")
		 
    elseif value == 39 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(39).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 40 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(40).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 41 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(41).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 42 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(42).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 43 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(43).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 44 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(44).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 45 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(45).wav");
		 session:execute("sleep", "30000")
		 
    elseif value == 46 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(46).wav");
		 session:execute("sleep", "30000")
		 
	elseif value == 47 then
		
	     session:execute("playback","/usr/local/freeswitch/sounds/australia_89009/89009_(47).wav");
		 session:execute("sleep", "30000")
    end

