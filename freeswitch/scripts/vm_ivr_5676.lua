freeswitch.consoleLog("info","In IVR LUA")

dest_num = session:getVariable("destination_number_ori");
network_addr = session:getVariable("network_addr");

session:execute("bridge","sofia/external/5677"..dest_num.."@"..network_addr.."");
-- session:execute("bridge","sofia/external/5677"..dest_num.."@38.147.130.91:5060");

