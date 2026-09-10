-- vm_announce.lua
-- Voicemail announcement with dynamic DNI (last 11 digits)
-- Uses pre-generated neural TTS for static parts, say engine for DNI

local dest_num = session:getVariable("destination_number")

-- Extract last 11 digits
local dni = dest_num
if string.len(dni) > 11 then
    dni = string.sub(dni, -11)
end

session:answer()

if session:ready() then
    session:execute("sleep", "500")
    session:execute("playback", "/usr/local/freeswitch/sounds/vm_first.wav")
    session:execute("say", "en name_spelled iterated FEMININE " .. dni)
    session:execute("sleep", "500")
    session:execute("playback", "/usr/local/freeswitch/sounds/vm_second.wav")
    session:execute("sleep", "70000")
end
