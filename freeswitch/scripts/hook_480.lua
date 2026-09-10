dat = env:getHeader("uuid")      
freeswitch.consoleLog("INFO"," <<<<< >>>>>> Inside hangup hook, uuid is: <<<<<< >>>>>> " .. dat .. "\n");                          
hangup_cause = env:getHeader("Hangup-Cause");
freeswitch.consoleLog("INFO"," <<<<< >>>>>> Channel-Hangup-Cause : <<<<<< >>>>>> " .. tostring(hangup_cause) .. "\n")   
env:addHeader("Hangup-Cause", "NO_ANSWER");
