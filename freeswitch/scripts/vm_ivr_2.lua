freeswitch.consoleLog("info","In IVR LUA")

dest_num = session:getVariable("destination_number_ori");

session:answer()

if session:ready() then

        session:execute("playback","/usr/local/freeswitch/sounds/new_ivr2.wav");

        session:execute("sleep", "180000")

        session:execute("lua","vm_ivr_2.lua")

end
