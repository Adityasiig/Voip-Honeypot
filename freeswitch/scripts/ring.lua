freeswitch.consoleLog("info"," [Ring] ");

-- if not _G._rng_seeded then math.randomseed(os.time()); _G._rng_seeded = true end -- guarded randomseed
-- math.random(); math.random(); math.random() -- warming up

-- For PDD 
local random = math.random(1333, 3300)
freeswitch.consoleLog("info"," [RANDOM] " ..tostring(random));
session:execute("sleep",""..tostring(random).."");

--[[-- For Milliseconds
local random1 = math.random(1000, 5500)
session:execute("ring_ready");
session:execute("sleep",""..tostring(random1).."");

-- For Milliseconds
local random2 = math.random(333, 999)
session:execute("ring_ready");
session:execute("sleep",""..tostring(random2).."");
--]]

-- random generating 
     m_value = math.random(1,6)
     print(value)

if m_value == 1 then
	 session:execute("ring_ready");
	 session:execute("sleep","100");
 elseif m_value == 2 then
	 session:execute("ring_ready");
	 session:execute("sleep","300");
 elseif m_value == 3 then
	 session:execute("ring_ready");
	 session:execute("sleep","450");
 elseif m_value == 4 then
     session:execute("ring_ready");
	 session:execute("sleep","350");
 elseif m_value == 5 then
	 session:execute("ring_ready");
	 session:execute("sleep","250");
 elseif m_value == 6 then
	 session:execute("ring_ready");
	 session:execute("sleep","550");
 end

--[[-- For Ringing
-- random generating 
     m_value1 = math.random(1,6)
     print(value)

if m_value1 == 1 then
	 session:execute("ring_ready");
	 session:execute("sleep","100");
 elseif m_value1 == 2 then
	 session:execute("ring_ready");
	 session:execute("sleep","300");
 elseif m_value1 == 3 then
	 session:execute("ring_ready");
	 session:execute("sleep","450");
 elseif m_value1 == 4 then
     session:execute("ring_ready");
	 session:execute("sleep","350");
 elseif m_value1 == 5 then
	 session:execute("ring_ready");
	 session:execute("sleep","250");
 elseif m_value1 == 6 then
	 session:execute("ring_ready");
	 session:execute("sleep","550");
 end
--]]

-- random generating 
	 cond_value = math.random(1,10)
	 print(value);

 if cond_value == 1 then

 	-- random generating 
	 value = math.random(3,17)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

 elseif cond_value == 2 then
 	-- random generating 
	 value = math.random(3,10)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

 elseif cond_value == 3 then
 	-- random generating 
	 value = math.random(3,23)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

 elseif cond_value == 4 then
 	-- random generating 
	 value = math.random(3,20)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

 elseif cond_value == 5 then
 	-- random generating 
	 value = math.random(3,19)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

 elseif cond_value == 6 then
 	-- random generating 
	 value = math.random(3,12)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");
elseif cond_value == 7 then
 	-- random generating 
	 value = math.random(3,16)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

elseif cond_value == 8 then
 	-- random generating 
	 value = math.random(3,20)	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");
elseif cond_value == 9 then
 	-- random generating 
	 value = math.random(3,21)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");

elseif cond_value == 10 then
 	-- random generating 
	 value = math.random(3,22)
	 print(value);
	 session:execute("set","playback_timeout_sec="..tostring(value).."");
	 session:execute("playback","/usr/local/freeswitch/sounds/ringing3366.wav");
end

-- For Milliseconds
local random4 = math.random(100,999)
session:execute("sleep",""..tostring(random4).."");
