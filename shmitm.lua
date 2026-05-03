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

    if data_len > 0 then
        subtree:add(f_data, buf(5, data_len))
        pinfo.cols.info = string.format("pid=%-6d  %-6s  %d bytes", pid, name, data_len)
    else
        pinfo.cols.info = string.format("pid=%-6d  %-6s  (no data)", pid, name)
    end
end

DissectorTable.get("wtap_encap"):add(wtap.USER0, shmitm)
