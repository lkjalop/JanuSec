-- Fluent Bit Lua filter: map generic JSON logs to IngestEvent schema
-- Input record is a Lua table 'record'
-- Output must set 'id', 'details', and optional 'domain', 'process', 'parent_process'

function map_ingest_event(tag, timestamp, record)
    local out = {}
    -- Try to map common fields; adjust as needed for your source
    out["id"] = record["event_id"] or record["id"] or tostring(timestamp)
    -- Build details.process map expected by IngestEvent
    local proc = {}
    proc["name"] = record["process_name"] or (record["process"] and record["process"]["name"]) or record["proc"] or record["image"]
    proc["parent_name"] = record["parent_process_name"] or (record["parent_process"] and record["parent_process"]["name"]) or record["parent"]
    local details = record["details"] or {}
    details["process"] = details["process"] or proc
    if record["domain"] then details["domain"] = record["domain"] end
    out["details"] = details
    if record["domain"] then out["domain"] = record["domain"] end
    -- Pass through any destination fields if present
    if record["dst_ip"] then out["dst_ip"] = record["dst_ip"] end
    if record["dst_port"] then out["dst_port"] = record["dst_port"] end
    return 1, timestamp, out
end