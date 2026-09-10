-- database connection using odbc
 dbh = freeswitch.Dbh("odbc://freeswitch")
 if dbh:connected() == false then
  freeswitch.consoleLog("notice", "=============== Database Connection Error.=============== ");
  return;
 end
  assert(dbh:connected())
  
session:answer();
caller_id_number = session:getVariable("caller_id_number");

if session:answered() then

	freeswitch.consoleLog("info","[Recrod Session]  Reording started");
	
	 d = os.date("%Y-%m-%d-%H-%M-%S");
		
	filename = ""..caller_id_number.."_"..d..".wav"
	recording_name="/var/www/html/"..filename.."";
	
		freeswitch.consoleLog("info","[Recrod Session]  Reording started".. recording_name);

	session:execute("record_session",recording_name);
	

	dbh:query("INSERT INTO recordings (filename,caller_number) VALUES('"..filename.."','"..caller_id_number.."')");

	session:execute("conference","${uuid}_${caller_id_number}_${domain_name}@default");
	
	-- close everything
end