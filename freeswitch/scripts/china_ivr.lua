freeswitch.consoleLog("info"," [china IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed

session:execute("sched_hangup", "+15 alotted_timeout");

for x = 1,3 do
    -- random generating 
    value = math.random(1,3)
    print(value)

     session:answer();
	freeswitch.consoleLog("info"," [china IVR] VALUE ".. value);

     if value == 1 then
	     session:execute("playback","/usr/local/freeswitch/sounds/china/china1.wav");
     elseif value == 2 then
	     session:execute("playback","/usr/local/freeswitch/sounds/china/china2.wav");
     elseif value == 3 then
	     session:execute("playback","/usr/local/freeswitch/sounds/china/china3.wav");
     end

end
