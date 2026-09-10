freeswitch.consoleLog("info"," [china IVR] ");

if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed

for x = 1,1 do
    -- random generating 
    value = math.random(1,8)
    print(value)

     if value == 1 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa1.wav");
     elseif value == 2 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa2.wav");
     elseif value == 3 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa3.wav");
     elseif value == 4 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa4.wav");
     elseif value == 5 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa5.wav");
     elseif value == 6 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa6.wav");
     elseif value == 7 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa7.wav");
     elseif value == 8 then
	     session:execute("playback","/usr/local/freeswitch/sounds/USA/usa8.wav");
     end
	session:hangup("ORIGINATOR_CANCEL");
end