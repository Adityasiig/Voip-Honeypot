-- Evidence-based pre-answer spam gate for the 3366 honeypot route.
-- Sets spam_gate_pass=true only when the configured risk threshold is met.

local CONFIG_FILE = "/opt/voip/spam_filter.conf"
local REPUTATION_DIR = "/opt/voip/spam_reputation_current"
local ALLOW_ANI_FILE = "/opt/voip/spam_allow_ani.txt"
local ALLOW_IP_FILE = "/opt/voip/spam_allow_ip.txt"
local FORCE_ANI_FILE = "/opt/voip/spam_force_ani.txt"
local FORCE_IP_FILE = "/opt/voip/spam_force_ip.txt"
local EVENT_DIR = "/opt/voip/spam_events"
local DECISION_DIR = "/opt/voip/spam_decisions"

local function digits(value)
    return (tostring(value or ""):gsub("[^%d]", ""))
end

local function read_config(path)
    local values = {}
    local f = io.open(path, "r")
    if not f then return values end
    for line in f:lines() do
        line = line:gsub("#.*$", ""):gsub("^%s+", ""):gsub("%s+$", "")
        local key, value = line:match("^([A-Za-z0-9_]+)%s*=%s*(.-)%s*$")
        if key and value then values[key:upper()] = value end
    end
    f:close()
    return values
end

local function read_set(path)
    local values = {}
    local f = io.open(path, "r")
    if not f then return values end
    for line in f:lines() do
        line = line:gsub("#.*$", ""):gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" then values[line] = true end
    end
    f:close()
    return values
end

local function as_bool(value, fallback)
    if value == nil then return fallback end
    value = tostring(value):lower()
    return value == "1" or value == "true" or value == "yes" or value == "on"
end

local function append_line(path, line)
    local f = io.open(path, "a")
    if not f then return false end
    f:write(line, "\n")
    f:close()
    return true
end

local ani = digits(session:getVariable("caller_id_number") or
                   session:getVariable("sip_from_user"))
if ani == "" then ani = "unknown" end
local dni = session:getVariable("destination_number_ori") or
            session:getVariable("destination_number") or ""
dni = digits(dni:gsub("^3366", "", 1))
if dni == "" then dni = "unknown" end
local sig_ip = session:getVariable("sip_received_ip") or
               session:getVariable("network_addr") or
               session:getVariable("sip_network_ip") or "unknown"
sig_ip = sig_ip:gsub("[\r\n\t ]", "")
local identity = session:getVariable("sip_h_Identity") or
                 session:getVariable("sip_h_identity") or
                 session:getVariable("sip_identity") or ""
local verstat = session:getVariable("sip_verstat") or
                session:getVariable("verstat") or
                session:getVariable("sip_h_Verstat") or ""
local uuid = session:get_uuid()

local config = read_config(CONFIG_FILE)
local threshold = tonumber(config.THRESHOLD) or 50
local lookback_seconds = tonumber(config.LOOKBACK_SECONDS) or 300
local ip_call_threshold = tonumber(config.IP_CALL_THRESHOLD) or 10
local ani_call_threshold = tonumber(config.ANI_CALL_THRESHOLD) or 5
local dni_sweep_threshold = tonumber(config.DNI_SWEEP_THRESHOLD) or 4
local enforce = as_bool(config.ENFORCE, true)

local allow_ani = read_set(ALLOW_ANI_FILE)
local allow_ip = read_set(ALLOW_IP_FILE)
local force_ani = read_set(FORCE_ANI_FILE)
local force_ip = read_set(FORCE_IP_FILE)

local function reputation_lookup(number)
    if not number:match("^%d+$") or #number < 10 or #number > 15 then
        return 0, 0, ""
    end
    local f = io.open(REPUTATION_DIR .. "/" .. number:sub(1, 3) .. ".tsv", "r")
    if not f then return 0, 0, "" end
    local complaints, robocalls, last_seen = 0, 0, ""
    for line in f:lines() do
        local n, c, r, d = line:match("^(%d+)%s+(%d+)%s+(%d+)%s+(%S+)")
        if n == number then
            complaints = tonumber(c) or 0
            robocalls = tonumber(r) or 0
            last_seen = d or ""
            break
        end
    end
    f:close()
    return complaints, robocalls, last_seen
end

-- FTC DNC shards store 10-digit national numbers; ANIs arrive as 11-digit (1NXXNXXXXXX).
local function reputation_for(number)
    local c, r, d = reputation_lookup(number)
    if c == 0 and #number == 11 and number:sub(1, 1) == "1" then
        c, r, d = reputation_lookup(number:sub(2))
    elseif c == 0 and #number == 10 then
        c, r, d = reputation_lookup("1" .. number)
    end
    return c, r, d
end

local function recent_behaviour(now)
    local ip_calls, ani_calls, ani_dnis = 0, 0, {}
    local function inspect(path)
        local f = io.open(path, "r")
        if not f then return end
        for line in f:lines() do
            local event_ts, event_ani, event_dni, event_ip =
                line:match("^(%d+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)")
            event_ts = tonumber(event_ts)
            if event_ts and now - event_ts >= 0 and now - event_ts <= lookback_seconds then
                if event_ip == sig_ip then ip_calls = ip_calls + 1 end
                if event_ani == ani then
                    ani_calls = ani_calls + 1
                    ani_dnis[event_dni] = true
                end
            end
        end
        f:close()
    end
    inspect(EVENT_DIR .. "/" .. os.date("%Y%m%d", now) .. ".tsv")
    inspect(EVENT_DIR .. "/" .. os.date("%Y%m%d", now - 86400) .. ".tsv")
    local unique_dnis = 0
    for _ in pairs(ani_dnis) do unique_dnis = unique_dnis + 1 end
    return ip_calls + 1, ani_calls + 1, unique_dnis + (ani_dnis[dni] and 0 or 1)
end

local score, reasons = 0, {}
local function add(points, reason)
    score = score + points
    reasons[#reasons + 1] = reason
end

local trusted_exclusion = allow_ani[ani] or allow_ip[sig_ip]
if force_ani[ani] then add(100, "MANUAL_SPAM_ANI") end
if force_ip[sig_ip] then add(100, "MANUAL_SPAM_IP") end

local complaints, robocalls, last_seen = reputation_for(ani)
if complaints > 0 then add(50, "FTC_COMPLAINT_MATCH") end
if complaints >= 3 then add(10, "REPEATED_FTC_COMPLAINTS") end
if robocalls > 0 then add(10, "FTC_ROBOCALL_REPORTED") end
if ani == "unknown" or #ani < 10 or #ani > 15 then add(20, "INVALID_ANI_FORMAT") end
if identity == "" then add(8, "STIR_IDENTITY_MISSING") end
if verstat:lower():find("fail", 1, true) then add(20, "STIR_VERIFICATION_FAILED") end

local now = os.time()
local ip_calls, ani_calls, unique_dnis = recent_behaviour(now)
if ip_calls >= ip_call_threshold then add(20, "HIGH_SOURCE_IP_VELOCITY") end
if ani_calls >= ani_call_threshold then add(25, "HIGH_ANI_VELOCITY") end
if unique_dnis >= dni_sweep_threshold then add(20, "DNI_SWEEP") end

local reason_text = table.concat(reasons, ",")
local verdict
if trusted_exclusion then
    verdict = "trusted_excluded"
elseif score >= 85 then
    verdict = "suspected_fraud"
elseif score >= 70 then
    verdict = "high_risk"
elseif score >= threshold then
    verdict = "spam_likely"
else
    verdict = "not_spam"
end

local accepted = (not trusted_exclusion) and score >= threshold
if not enforce then accepted = true end
session:setVariable("spam_score", tostring(score))
session:setVariable("spam_verdict", verdict)
session:setVariable("spam_reasons", reason_text)
session:setVariable("spam_ftc_complaints", tostring(complaints))
session:setVariable("spam_ftc_robocalls", tostring(robocalls))
session:setVariable("spam_ftc_last_seen", last_seen)
session:setVariable("spam_gate_pass", accepted and "true" or "false")

append_line(EVENT_DIR .. "/" .. os.date("%Y%m%d", now) .. ".tsv",
    table.concat({now, ani, dni, sig_ip, uuid}, "\t"))
append_line(DECISION_DIR .. "/" .. os.date("%Y%m%d", now) .. ".tsv",
    table.concat({now, ani, dni, sig_ip, score, verdict,
                  reason_text ~= "" and reason_text or "NONE", complaints,
                  robocalls, last_seen ~= "" and last_seen or "NONE", uuid}, "\t"))

if accepted then
    session:consoleLog("notice", string.format(
        "[3366 spam-gate] ACCEPT ani=%s dni=%s ip=%s score=%d verdict=%s reasons=%s\n",
        ani, dni, sig_ip, score, verdict, reason_text))
else
    session:consoleLog("notice", string.format(
        "[3366 spam-gate] REJECT ani=%s dni=%s ip=%s score=%d verdict=%s reasons=%s\n",
        ani, dni, sig_ip, score, verdict, reason_text))
    session:execute("respond", "603 Declined")
end
