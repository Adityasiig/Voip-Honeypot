-- if (session:ready()) then

	api = freeswitch.API();

	--session:execute("curl", "http://www.myhost.com/?name1=value1&name2=value2")
	--curl_response_code = session:getVariable("curl_response_code")
	--curl_response      = session:getVariable("curl_response_data")
	checknum = session:getVariable("destination_number");


	local auth_url = "curl --location --request POST 'http://85.195.107.127/number/index.php/api/check-number' --header 'Content-Type: application/json' --data-raw '{number:"..checknum.."}'"
	
	--local response = api:executeString("curl", auth_url);
	
	curl_response = os.execute(auth_url);


	freeswitch.consoleLog("info","  [Call Blocking]  Response : ".. tostring(curl_response));
	
	-- checknum = session:getVariable("destination_number");
	-- os.execute('echo ' .. checknum .. ' >> /opt/test.log');

--	local handle = io.popen(/opt/check.sh)  --	local result = handle:read("*a")  	--	handle:close()
	--os.execute('echo ' .. result .. ' >> /opt/test.log');

--	local http_request = require "http.request"
--	local headers, stream = assert(http_request.new_from_uri(""):go())
--	local body = assert(stream:get_body_as_string())
	--if headers:get ":status" ~= "200" then
	  --  error(body)
	--end
--	print(body)

--	res = os.execute('/opt/check.sh');
--	os.execute('echo ' .. res .. ' >> /opt/test.log');
	
	if curl_response == "YES" then
		os.execute('echo "Number matched continuing call" >> /opt/test.log')
		return;
	else
		os.execute('echo "Number not matched hanging up" >> /opt/test.log')
		session:hangup("DESTINATION_OUT_OF_ORDER");
	end

-- end
