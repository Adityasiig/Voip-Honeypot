freeswitch.consoleLog("info","In IVR LUA")
dest_num = session:getVariable("destination_number_ori")
session:answer()
if session:ready() then
    session:execute("playback","/usr/local/freeswitch/sounds/start3366.wav")
    session:execute("say","en name_spelled iterated FEMININE " .. dest_num)
    session:execute("playback","/usr/local/freeswitch/sounds/end3366.wav")
    session:execute("sleep", "120000")
    session:hangup()
end
