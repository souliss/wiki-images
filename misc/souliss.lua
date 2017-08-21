--------------------------------------------------------------------
-- 
-- souliss protocol dissector for WireShark
--
-- How to install:
--
-- 1. Find your plugins folder in WireShark menu: Help -> About Wireshark
--    -> Folders tab -> "Personal plugins"
--
-- 2. Create the folder if it does not exist
--
-- 3. Put this file (filename: souliss.lua) in that folder
--
-- 4. Restart wireshark
--
-- 5. Now you can see Souliss packages, with some information about
--    vnet frames and macaco protocol
--
--------------------------------------------------------------------

souliss_proto = Proto("souliss","Souliss Protocol")

--------------------------------------------------------------------
-- 
-- logic description
--
--------------------------------------------------------------------
lg = {}

lg[0x10] = "Typicals Group 0x10"
lg[0x20] = "Typicals Group 0x20"
lg[0x30] = "Typicals Group 0x30"
lg[0x40] = "Typicals Group 0x40"
lg[0x50] = "Typicals Group 0x50"
lg[0x60] = "Typicals Group 0x60"
lg[0x11] = "ON/OFF Digital Output with Timer Option"
lg[0x12] = "ON/OFF Digital Output with AUTO mode"
lg[0x13] = "Digital Input Value"
lg[0x14] = "Pulse Digital Output"
lg[0x15] = "RGB Light (IR)"
lg[0x16] = "RGB Light"
lg[0x18] = "ON/OFF Digital Output with pulse output with Timer Option"
lg[0x19] = "LED Light"
lg[0x21] = "Motorized devices with limit switches"
lg[0x22] = "Motorized devices with limit switches and middle position"
lg[0x31] = "Temperature control"
lg[0x32] = "Air Conditioner"
lg[0x41] = "Anti-theft integration (Main)"
lg[0x42] = "Anti-theft integration (Peer)"
lg[0x51] = "Generic"
lg[0x52] = "Temperature measure (-20, +50) °C"
lg[0x53] = "Humidity measure (0, 100) %"
lg[0x54] = "Light Sensor (0, 40) kLux"
lg[0x55] = "Voltage (0, 400) V"
lg[0x56] = "Current (0, 25)  A"
lg[0x57] = "Power (0, 6500)  W"
lg[0x58] = "Pressure measure (0, 1500) hPa"
lg[0x59] = "Unknown"
lg[0x61] = "Generic"
lg[0x62] = "Temperature measure (-20, +50) °C"
lg[0x63] = "Humidity measure (0, 100) %"
lg[0x64] = "Light Sensor (0, 40) kLux"
lg[0x65] = "Voltage (0, 400) V"
lg[0x66] = "Current (0, 25)  A"
lg[0x67] = "Power (0, 6500)  W"
lg[0x68] = "Pressure measure (0, 1500) hPa"
lg[0x69] = "Unknown"
--------------------------------------------------------------------
-- 
-- functional codes
--
--------------------------------------------------------------------
fc = {}


fc[0x01] = "Read request for digital value"
fc[0x11] = "Read answer for digital value"
fc[0x02] = "Read request for analog value"
fc[0x12] = "Read answer for analog value"
fc[0x05] = "Subscription reques"
fc[0x15] = "Subscription answe"
fc[0x13] = "Force back a register valu"
fc[0x14] = "Force a register valu"
fc[0x16] = "Force a register value (bit-wise AND)"
fc[0x17] = "Force a register value (bit-wise OR)"
fc[0x08] = "Ping request"
fc[0x18] = "Ping answer"
fc[0x09] = "Trace root request (Functional code not supported)"
fc[0x19] = "Trace root answer (Functional code not supported)"
fc[0x83] = "General Error"
fc[0x84] = "Data out of range"
fc[0x85] = "Subscription refused"
fc[0x21] = "Read state request with subscription"
fc[0x31] = "Read state answer"
fc[0x22] = "Read typical logic request"
fc[0x32] = "Read typical logic answer"
fc[0x33] = "Force input values"
fc[0x34] = "Force input values by typical logic,"
fc[0x25] = "Nodes healthy request"
fc[0x35] = "Nodes healthy answer"
fc[0x26] = "Database structure request"
fc[0x36] = "Database structure answer"
fc[0x27] = "Read state request without subscription"
fc[0x37] = "Read state answer without subscription"
fc[0x28] = "Discover a gateway node request (broadcast)"
fc[0x38] = "Discover a gateway node answer (broadcast)"
fc[0x29] = "Dynamic addressing request (broadcast)"
fc[0x39] = "Dynamic addressing answer (broadcast)"
fc[0x2A] = "Subnet request (broadcast"
fc[0x3A] = "Subnet answer (broadcast"
fc[0x2B] = "Join a network gateway (broadcast)"
fc[0x2C] = "Join a network gateway and reset (broadcast)"
fc[0x2D] = "Set an IP address at runtime (broadcast)"
fc[0x2E] = "Set a WiFi SSID at runtime (broadcast)"
fc[0x2F] = "Set a WiFi Password at runtime (broadcast)"
fc[0x71] = "Force input values by typical logic (broadcast or multicast"
fc[0x72] = "Send an Action Message (broadcast or multicast)"

--------------------------------------------------------------------
-- 
-- local disectors for specific messages
--
--------------------------------------------------------------------


function souliss_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "Souliss"
    local subtree = tree:add(souliss_proto,buffer(),"Souliss Protocol Data")

    _length = buffer(1,1):uint()
    subtree:add(buffer(0,1),"Length: " .. buffer(0,1):uint())
    subtree:add(buffer(1,1),"Length + 1: " .. buffer(1,1):uint())
    subtree:add(buffer(2,1),"Port: " .. buffer(2,1):uint())
    subtree:add(buffer(3,2),"Final destination: " .. tostring(buffer(3,2):bytes()))
    subtree:add(buffer(5,2),"Original destination: " .. tostring(buffer(5,2):bytes()))

    local subtree = tree:add(buffer(6, _length-7),"MaCaco frame")

    _functional_code = buffer(7,1):uint()
    _fc_description = fc[_functional_code]
    _number_of = buffer(11,1):uint()

    if _fc_description == nil then
        -- pinfo.cols.info = "*** UNKNOWN FUNCTIONAL CODE .. _functional_code .. " ***"
        _fc_description = "Unknown"
        pinfo.cols.info = "*** UNKNOWN FUNCTIONAL CODE ***"
    else
        pinfo.cols.info = _fc_description
    end

    subtree:add(buffer(7,1),"Functional code: " .. _functional_code .. " -> " .. _fc_description)
    subtree:add(buffer(8,2),"Putin: " .. tostring(buffer(8,2):bytes()))
    subtree:add(buffer(10,1),"Start offset: " .. buffer(10,1):uint())
    subtree:add(buffer(11,1),"Number off: " .. buffer(11,1):uint())

    if (_functional_code == 0x36 ) then -- database structure answer
        subtree:add(buffer(12,1), "Nodes configured: " .. buffer(12,1):uint())
        subtree:add(buffer(13,1), "Allowed nodes: " .. buffer(13,1):uint())
        subtree:add(buffer(14,1), "Maximum slots per node: " .. buffer(14,1):uint())
        subtree:add(buffer(15,1), "Maximum subscribers: " .. buffer(15,1):uint())
    elseif (_functional_code == 0x32 ) then -- read typical logic answer
        for i=1,_number_of do
            logic = lg[buffer(11 + i, 1):uint()]
            if logic == nil then 
                logic = "*** UNKNOWN ***"
            end
            subtree:add(buffer(11+i,1), "Node: " .. logic)
        end
    end
    --subtree:add(buffer(10,1),"Payload: " .. buffer(10,1):uint())
    --subtree = subtree:add(buffer(2,2),"The next two bytes")
    --subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    --subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(230,souliss_proto)
