freeswitch.consoleLog("info","In IVR LUA")

dest_num = session:getVariable("destination_number_ori");

session:answer();

if session:ready() then

        session:execute("playback","/usr/local/freeswitch/sounds/new_vm/rec_1_part1.wav");

        session:execute("say","en name_spelled iterated FEMININE ".. dest_num);

        session:execute("playback","/usr/local/freeswitch/sounds/new_vm/rec_1_part2.wav");

        session:execute("sleep", "180000")

        session:execute("lua","vm_ivr_1.lua")

end
