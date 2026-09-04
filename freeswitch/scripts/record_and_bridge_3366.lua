-- record_and_bridge_3366.lua
-- Spam-only admission gate removed: all valid 3366 calls continue to recording and bridging.
-- USA prefix 3366: answer, record the A-leg, bridge to the configured vendor.
-- Vendor endpoint + tech-prefix are read live from plain files so they can be
-- changed from the frontend without a reloadxml or FreeSWITCH restart.
-- Recording filename encodes: date, time, ANI (caller), DNI (dialed), uuid.

local VENDOR_FILE = "/opt/voip/vendor_3366.conf"
local PREFIX_FILE = "/opt/voip/vendor_3366_prefix.conf"
local REC_DIR     = "/opt/voip/recordings"

local function read_first_line(path)
    local f = io.open(path, "r")
    if not f then return nil end
    for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            f:close()
            return line
        end
    end
    f:close()
    return nil
end

local function read_vendor() return read_first_line(VENDOR_FILE) end
local function read_prefix() return read_first_line(PREFIX_FILE) or "" end

local function digits(s)
    if not s then return "" end
    return (s:gsub("[^%d]", ""))
end

-- DNI: the dialed number (digits after the 3366 prefix)
local dest = session:getVariable("destination_number_ori")
if not dest or dest == "" then
    dest = session:getVariable("destination_number") or "unknown"
end
-- Strip the 3366 routing prefix if it survived (fallback path / alt dialplan),
-- so both the vendor bridge and the DNI display use the real dialed number.
dest = dest:gsub("^3366", "", 1)
if dest == "" then dest = "unknown" end

-- ANI: the caller's number
local ani = session:getVariable("caller_id_number")
if not ani or ani == "" then
    ani = session:getVariable("sip_from_user") or ""
end

local dni_s = digits(dest); if dni_s == "" then dni_s = "unknown" end
local ani_s = digits(ani);  if ani_s == "" then ani_s = "unknown" end

local uuid    = session:get_uuid()
local ts      = os.date("%Y%m%d_%H%M%S")
local recfile = REC_DIR .. "/3366_" .. ts .. "_" .. ani_s .. "_" .. dni_s .. "_" .. uuid .. ".wav"
local vendor  = read_vendor()
local prefix  = read_prefix()

local meta_path = recfile:gsub("%.wav$", ".meta")
local sig_ip = session:getVariable("sip_received_ip") or
               session:getVariable("network_addr") or
               session:getVariable("sip_network_ip") or ""
-- Only allow an IP-literal value into outbound SIP headers.
if not sig_ip:match("^[0-9A-Fa-f:.]+$") then sig_ip = "" end
local media_ip = session:getVariable("remote_media_ip") or ""
-- remote_media_ip comes from the inbound SDP and is the carrier's negotiated
-- RTP endpoint. Only forward a literal IP; never copy arbitrary SDP text into
-- a SIP header. Fall back to the signaling peer when no media IP is available.
if not media_ip:match("^[0-9A-Fa-f:.]+$") then media_ip = "" end
if media_ip == "" or media_ip == "0.0.0.0" then media_ip = sig_ip end
-- Prefer the media address ADVERTISED in the inbound SDP c= line over the
-- latched RTP source (remote_media_ip). Upstream advertises its real media IP
-- (e.g. 149.210.145.184) in c=, but FS latches remote_media_ip to the RTP/
-- signaling source (e.g. 38.65.82.54 -- inside the vendor's own /24 -> 482).
local remote_sdp = session:getVariable("switch_r_sdp") or ""
local sdp_c_ip = remote_sdp:match("c=IN IP4%s+([0-9%.]+)") or ""
if sdp_c_ip:match("^[0-9%.]+$") and sdp_c_ip ~= "0.0.0.0" then media_ip = sdp_c_ip end
local original_media_ip = media_ip
local identity_header = session:getVariable("sip_h_Identity") or
                        session:getVariable("sip_h_identity") or
                        session:getVariable("sip_identity") or ""
identity_header = identity_header:gsub("[\r\n]", "")
local pai_header = session:getVariable("sip_h_P-Asserted-Identity") or ""
pai_header = pai_header:gsub("[\r\n]", "")
local verstat = session:getVariable("sip_verstat") or
                session:getVariable("verstat") or
                session:getVariable("sip_h_Verstat") or ""
if verstat == "" then
    verstat = pai_header:match("[vV][eE][rR][sS][tT][aA][tT]=([^;>,%s]+)") or ""
end
local user_agent = (session:getVariable("sip_user_agent") or ""):gsub("[\r\n]", "")
local via_host = (session:getVariable("sip_via_host") or ""):gsub("[\r\n]", "")

local function json_escape(value)
    local text = tostring(value or "")
    return (text:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\r", "\\r"):gsub("\n", "\\n"))
end

local function write_meta(sip_code, sip_reason, sip_state, hangup_cause, originate_disposition, connected)
    local connected_json = "null"
    if connected ~= nil then connected_json = connected and "true" or "false" end
    local mf = io.open(meta_path, "w")
    if not mf then return end
    mf:write(string.format(
        '{"media_ip":"%s","sig_ip":"%s","ani":"%s","dni":"%s","sip_code":"%s","sip_reason":"%s","sip_state":"%s","hangup_cause":"%s","originate_disposition":"%s","connected":%s,"identity_header":"%s","verstat":"%s","pai_header":"%s","user_agent":"%s","via_host":"%s"}',
        json_escape(media_ip), json_escape(sig_ip), json_escape(ani_s), json_escape(dni_s),
        json_escape(sip_code), json_escape(sip_reason), json_escape(sip_state),
        json_escape(hangup_cause), json_escape(originate_disposition), connected_json,
        json_escape(identity_header), json_escape(verstat), json_escape(pai_header),
        json_escape(user_agent), json_escape(via_host)))
    mf:close()
end

local SIP_REASONS = {
    ["200"] = "Connected", ["404"] = "Not found", ["408"] = "Request timeout",
    ["480"] = "Temporarily unavailable", ["486"] = "Busy", ["487"] = "Caller cancelled",
    ["488"] = "Not acceptable", ["500"] = "Server error", ["502"] = "Bad gateway",
    ["503"] = "Temporary failure", ["603"] = "Declined"
}
local DISPOSITION_TO_SIP = {
    SUCCESS = "200", CALL_REJECTED = "603", NORMAL_TEMPORARY_FAILURE = "503",
    USER_BUSY = "486", NO_ANSWER = "480", NO_USER_RESPONSE = "408",
    ORIGINATOR_CANCEL = "487", UNALLOCATED_NUMBER = "404",
    DESTINATION_OUT_OF_ORDER = "502", NORMAL_CIRCUIT_CONGESTION = "503",
    INCOMPATIBLE_DESTINATION = "488", RECOVERY_ON_TIMER_EXPIRE = "408"
}

local function persist_bridge_result()
    local disposition = session:getVariable("originate_disposition") or ""
    local bridge_cause = session:getVariable("bridge_hangup_cause") or ""
    local proto_cause = session:getVariable("last_bridge_proto_specific_hangup_cause") or
                        session:getVariable("proto_specific_hangup_cause") or ""
    local sip_code = proto_cause:match("[sS][iI][pP][%s:/]+(%d%d%d)") or DISPOSITION_TO_SIP[disposition] or ""
    local connected = disposition == "SUCCESS"
    if connected then sip_code = "200" end
    local sip_reason = SIP_REASONS[sip_code] or (sip_code ~= "" and "SIP response" or "Call ended")
    local hangup_cause = bridge_cause ~= "" and bridge_cause or disposition
    write_meta(sip_code, sip_reason, connected and "connected" or "failed", hangup_cause, disposition, connected)
end

-- TERM-SPOOF (A-leg): advertise a random US pool IP as the terminating media IP
-- toward the customer, so their CDR TERM MEDIA IP shows a pool IP, not box 70.36.107.24.
-- INERT unless the flag file exists AND sig_ip matches the gated test source.
-- Media survives only if the customer latches (symmetric RTP) to our wire source.
if sig_ip == "38.65.82.54" then
    local _tflag = io.open("/var/lib/freeswitch/scripts/TERM_SPOOF_ON", "r")
    if _tflag then
        _tflag:close()
        local tpool = {}
        local tpf = io.open("/var/lib/freeswitch/scripts/media_pool.txt", "r")
        if tpf then
            for line in tpf:lines() do
                local ip = line:match("^%s*([0-9%.]+)%s*$")
                if ip then tpool[#tpool + 1] = ip end
            end
            tpf:close()
        end
        if #tpool > 0 then
            local tseed = os.time()
            local tu = session:getVariable("uuid") or ""
            for ch in tu:gmatch("%x") do tseed = tseed * 31 + tonumber(ch, 16) end
            math.randomseed(tseed)
            local tip = tpool[math.random(#tpool)]
            session:setVariable("rtp_adv_audio_ip", tip)
            session:consoleLog("info", "[3366] TERM adv_media_ip=" .. tip .. "\n")
        end
    end
end
session:answer()
-- Write a pending sidecar immediately, then replace it with the final SIP result
-- as soon as the vendor bridge returns.
write_meta("", "In progress", "pending", "", "", nil)
-- A-leg only: record just the read stream (inbound caller audio).
-- read = audio received from the caller on this leg; write (far-end/B-leg
-- vendor audio) is intentionally excluded.
session:execute("set", "RECORD_STEREO=false")
session:execute("set", "RECORD_READ_ONLY=true")
session:execute("record_session", recfile)

if vendor and vendor ~= "" then
    -- vendor authorizes by source IP + technical prefix (no digest auth),
    -- keyed to 70.36.107.24:5060 -> must egress from the internal profile
    -- (:5060). Sourcing from external (:5080) gets 401. Prepend the
    -- tech-prefix to the dialed number for the outbound leg only.
    -- Advertise the inbound carrier's negotiated media IP in the OUTBOUND SDP
    -- (c=/o= line) so the downstream vendor's CDR records the originating
    -- carrier's media IP instead of this FreeSWITCH box. FS still anchors RTP
    -- (A-leg recording stays intact); only the *advertised* address changes.
    -- The real packet source stays 70.36.107.24, so return media relies on the
    -- vendor doing symmetric RTP (latching) -- VOS3000/most carriers do.
    -- Rotating US media-IP pool (snapshot of OPS dr_gateways US gateways).
    -- Hides box 70.36.107.24: advertise a random plausible US IP in SDP c=/o=.
    -- Vendor validates c= by geo/reputation (US ok, foreign -> 408); latches media to wire source.
    local adv = ""
    local adv_ip = original_media_ip
    do
        local pool = {}
        local pf = io.open("/var/lib/freeswitch/scripts/media_pool.txt", "r")
        if pf then
            for line in pf:lines() do
                local ip = line:match("^%s*([0-9%.]+)%s*$")
                if ip then pool[#pool + 1] = ip end
            end
            pf:close()
        end
        if #pool > 0 then
            local seed = os.time()
            local u = session:getVariable("uuid") or ""
            for ch in u:gmatch("%x") do seed = seed * 31 + tonumber(ch, 16) end
            math.randomseed(seed)
            adv_ip = pool[math.random(#pool)]
            adv = "{rtp_adv_audio_ip=" .. adv_ip .. "}"
            session:consoleLog("info", "[3366] adv_media_ip=" .. adv_ip .. " pool=" .. #pool .. "\n")
        end
    end
    local dialstr = adv .. "sofia/internal/" .. prefix .. dni_s .. "@" .. vendor
    session:execute("set", "hangup_after_bridge=false")
    session:execute("set", "continue_on_fail=true")
    -- RESTORE 2026-09-02: session rtp_adv_audio_ip disabled; keep SDP c= = box IP  -- FRAUDSPOOF: advertise customer media IP in B-leg SDP
    if original_media_ip ~= "" then
        -- Populate the vendor-supported headers with the inbound carrier's
        -- negotiated RTP address, not this FreeSWITCH box or the SIP peer.
        -- The packet-level RTP source remains FreeSWITCH while recording is on.
        session:execute("bridge_export", "sip_h_X-Original-Source-IP=" .. adv_ip)
        session:execute("bridge_export", "sip_h_X-Orig-IP=" .. adv_ip)
    end
    -- Preserve an inbound STIR/SHAKEN PASSporT for the downstream provider.
    -- Presence alone is never treated as successful verification.
    if identity_header ~= "" then
        session:execute("bridge_export", "sip_h_identity=" .. identity_header)
    end
    session:consoleLog("info", "[3366] ani=" .. ani_s .. " dni=" .. dni_s .. " prefix=" .. prefix .. " -> " .. dialstr .. " rec=" .. recfile .. "\n")
    session:execute("bridge", dialstr)
    persist_bridge_result()
else
    write_meta("", "Vendor not configured", "failed", "NO_ROUTE_DESTINATION", "NO_ROUTE_DESTINATION", false)
    session:consoleLog("warning", "[3366] no vendor configured (" .. VENDOR_FILE .. "); holding then hangup\n")
    session:streamFile("/opt/files/ringingmono.wav")
    session:sleep(2000)
end

if session:ready() then
    session:hangup()
end
