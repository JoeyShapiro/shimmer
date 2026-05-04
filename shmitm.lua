-- shmitm.lua — Wireshark dissector for Shmitm pcap captures
-- Install: copy to ~/.config/wireshark/plugins/ (Linux/Mac) or %APPDATA%\Wireshark\plugins\ (Windows)
-- Link type: LINKTYPE_USER0 (DLT 220)
--
-- Payload layout per packet:
--   [0..3]  int32  PID        (little-endian)
--   [4]     uint8  StreamId
--   [5..]   bytes  data

local shmitm = Proto("shmitm", "Shmitm Process Stream")

local stream_names = {
    [0]  = "stdout",
    [1]  = "stderr",
    [2]  = "stdin",
    [10] = "start",
    [11] = "argv",
    [12] = "env",
    [13] = "end",
}

local f_pid    = ProtoField.int32 ("shmitm.pid",       "PID",       base.DEC)
local f_stream = ProtoField.uint8 ("shmitm.stream_id", "Stream ID", base.DEC, stream_names)
local f_data   = ProtoField.string("shmitm.data",      "Data",      base.UNICODE)

shmitm.fields = { f_pid, f_stream, f_data }

function shmitm.dissector(buf, pinfo, tree)
    if buf:len() < 5 then return end

    pinfo.cols.protocol = "Shmitm"

    local subtree = tree:add(shmitm, buf(), "Shmitm Process Stream")

    local pid       = buf(0, 4):le_int()
    local stream_id = buf(4, 1):uint()
    local data_len  = buf:len() - 5
    local name      = stream_names[stream_id] or string.format("unknown(%d)", stream_id)

    subtree:add_le(f_pid,    buf(0, 4))
    subtree:add   (f_stream, buf(4, 1))

    pinfo.cols.src = tostring(pid)
    pinfo.cols.dst = name

    if data_len > 0 then
        subtree:add(f_data, buf(5, data_len))
        pinfo.cols.info = string.format("%d bytes", data_len)
    else
        pinfo.cols.info = "(no data)"
    end
end

-- Field extractors must be created at the top level, not inside callbacks
local fld_pid    = Field.new("shmitm.pid")
local fld_stream = Field.new("shmitm.stream_id")
local fld_data   = Field.new("shmitm.data")

-- pipe_streams[pid] = ordered list of {stream_id, data}
local pipe_streams = {}

local tap = Listener.new("frame", "shmitm")

function tap.packet(pinfo, tvb, frame)
    local pid_fi    = fld_pid()
    local stream_fi = fld_stream()
    local data_fi   = fld_data()

    if not pid_fi or not stream_fi then return end

    local sid = stream_fi.value
    if sid ~= 0 and sid ~= 2 then return end  -- only stdout and stdin

    local pid = pid_fi.value
    if not pipe_streams[pid] then pipe_streams[pid] = {} end

    local data_str = data_fi and tostring(data_fi.value) or ""
    table.insert(pipe_streams[pid], { stream_id = sid, data = data_str })
end

function tap.reset()
    pipe_streams = {}
end

register_menu("Follow Process Pipe", function()
    new_dialog("Follow Process Pipe", function(pid_str)
        local pid = tonumber(pid_str)
        if not pid then return end

        local w = TextWindow.new("Process Pipe — PID " .. pid)

        local entries = pipe_streams[pid]
        if not entries or #entries == 0 then
            w:set("No stdin/stdout captured for PID " .. pid)
            return
        end

        local chunks = {}
        for _, e in ipairs(entries) do
            local prefix = e.stream_id == 0 and "[out] " or "[in]  "
            table.insert(chunks, prefix .. e.data)
        end
        w:set(table.concat(chunks, ""))
    end, "PID")
end, MENU_TOOLS_UNSORTED)

DissectorTable.get("wtap_encap"):add(wtap.USER0, shmitm)
