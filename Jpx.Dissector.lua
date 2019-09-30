-- JPX Protocol
local jpx = Proto("Jpx.Lua", "JPX")

-- Component Tables
local dissect = {}
local verify = {}
local options = {}


-----------------------------------------------------------------------
-- Declare Options 
-----------------------------------------------------------------------
options.empty_session_id = false

-- Register JPX Options
jpx.prefs.empty_session_id = Pref.bool("Empty session ID", options.empty_session_id, "Allow empty session ID (all zeros)")

-----------------------------------------------------------------------
-- Declare Protocol Fields
-----------------------------------------------------------------------
local packet_type_desc = {
  [65] = "A (New order)",
  [82] = "R (Series data basic)",
  [77] = "M (Series data basic: Combination trading instruments)",
  [76] = "L (Tick size data)",
  [83] = "S (System event data)",
  [81] = "O (Trading status data)",
  [69] = "E (Execution notice)",
  [67] = "C (Execution notice with trade information)",
  [84] = "T (Seconds)",
  [68] = "D (Delete order)",
  [80] = "P (Price notification)",
  [90] = "Z (Equilibrium price)",
}

local side_desc = {
  [66] = "Buy",
  [83] = "Sell"
}

-- JPX Fields
jpx.fields.packet_header = ProtoField.new("Packet Header", "jpx.packetheader", ftypes.NONE)
jpx.fields.session_id = ProtoField.new("Session ID", "jpx.sessionid", ftypes.STRING)
jpx.fields.seq_number = ProtoField.new("Sequence Number", "jpx.sequencenumber", ftypes.UINT64)
jpx.fields.message_count = ProtoField.new("Message Count", "jpx.messagecount", ftypes.UINT16)
jpx.fields.message = ProtoField.new("Message", "jpx.message", ftypes.NONE)
jpx.fields.message_length = ProtoField.new("Message Length", "jpx.messagelength", ftypes.UINT16)
jpx.fields.packet_type = ProtoField.new("Packet Type", "jpx.packettype", ftypes.UINT8, packet_type_desc)
-- Message Type T
jpx.fields.T_second = ProtoField.new("Second", "jpx.T.second", ftypes.ABSOLUTE_TIME)
-- Message Type A
jpx.fields.A_timestamp_ns = ProtoField.new("Timestamp ns", "jpx.A.timestampns", ftypes.UINT32)
jpx.fields.A_order_id = ProtoField.new("Order ID", "jpx.A.orderid", ftypes.UINT64, nil, base.HEX)
jpx.fields.A_order_book_id = ProtoField.new("Order Book ID", "jpx.A.orderbookid", ftypes.UINT32)
jpx.fields.A_side = ProtoField.new("Side", "jpx.A.side", ftypes.UINT8, side_desc)
jpx.fields.A_order_book_postition = ProtoField.new("Order Book Position", "jpx.A.orderbookposition", ftypes.UINT32)
jpx.fields.A_quantity = ProtoField.new("Quantity", "jpx.A.quantity", ftypes.UINT64)
jpx.fields.A_price = ProtoField.new("Price", "jpx.A.price", ftypes.UINT32)
jpx.fields.A_order_attributes = ProtoField.new("Order Attributes", "jpx.A.orderattributes", ftypes.UINT16)
jpx.fields.A_lot_type = ProtoField.new("Lot Type", "jpx.A.lottype", ftypes.UINT8)
-- Message Type E
jpx.fields.E_timestamp_ns = ProtoField.new("Timestamp ns", "jpx.E.timestampns", ftypes.UINT32)
jpx.fields.E_order_id = ProtoField.new("Order ID", "jpx.E.orderid", ftypes.UINT64, nil, base.HEX)
jpx.fields.E_order_book_id = ProtoField.new("Order Book ID", "jpx.E.orderbookid", ftypes.UINT32)
jpx.fields.E_side = ProtoField.new("Side", "jpx.E.side", ftypes.UINT8, side_desc)
jpx.fields.E_quantity = ProtoField.new("Quantity", "jpx.E.quantity", ftypes.UINT64)
jpx.fields.E_match_id = ProtoField.new("Match ID", "jpx.E.matchid", ftypes.UINT64)
jpx.fields.E_combo_group_id = ProtoField.new("Combo Group ID", "jpx.A.combogroupid", ftypes.UINT32)
jpx.fields.E_reserved_1 = ProtoField.new("Reserved", "jpx.E.reserved1", ftypes.STRING)
jpx.fields.E_reserved_2 = ProtoField.new("Reserved", "jpx.E.reserved2", ftypes.STRING)
-- Message Type D
jpx.fields.D_timestamp_ns = ProtoField.new("Timestamp ns", "jpx.D.timestampns", ftypes.UINT32)
jpx.fields.D_order_id = ProtoField.new("Order ID", "jpx.D.orderid", ftypes.UINT64, nil, base.HEX)
jpx.fields.D_order_book_id = ProtoField.new("Order Book ID", "jpx.D.orderbookid", ftypes.UINT32)
jpx.fields.D_side = ProtoField.new("Side", "jpx.D.side", ftypes.UINT8, side_desc)


-----------------------------------------------------------------------
-- Dissect functions
-----------------------------------------------------------------------
dissect.size_of = {
  message_type = 1,
  message_length = 2,
  session_id = 10,
}

dissect.packet_header_fields = {
  [0] = { pfield = jpx.fields.session_id, size = dissect.size_of.session_id },
  [1] = { pfield = jpx.fields.seq_number, size = 8},
  [2] = { pfield = jpx.fields.message_count, size = 2 },
}

dissect.message_fields_table = {
  ["A"] = {
    [0] = { pfield = jpx.fields.A_timestamp_ns, size = 4 },
    [1] = { pfield = jpx.fields.A_order_id, size = 8 },
    [2] = { pfield = jpx.fields.A_order_book_id, size = 4 },
    [3] = { pfield = jpx.fields.A_side, size = 1 },
    [4] = { pfield = jpx.fields.A_order_book_postition, size = 4 },
    [5] = { pfield = jpx.fields.A_quantity, size = 8 },
    [6] = { pfield = jpx.fields.A_price, size = 4 },
    [7] = { pfield = jpx.fields.A_order_attributes, size = 2 },
    [8] = { pfield = jpx.fields.A_lot_type, size = 1 },
  },
  ["T"] = {
    [0] = { pfield = jpx.fields.T_second, size = 4 },
  },
  ["R"] = {},
  ["M"] = {},
  ["L"] = {},
  ["S"] = {},
  ["O"] = {},
  ["E"] = {
    [0] = { pfield = jpx.fields.E_timestamp_ns, size = 4 },
    [1] = { pfield = jpx.fields.E_order_id, size = 8 },
    [2] = { pfield = jpx.fields.E_order_book_id, size = 4 },
    [3] = { pfield = jpx.fields.E_side, size = 1 },
    [4] = { pfield = jpx.fields.E_quantity, size = 8 },
    [5] = { pfield = jpx.fields.E_match_id, size = 8 },
    [6] = { pfield = jpx.fields.E_combo_group_id, size = 4 },
    [7] = { pfield = jpx.fields.E_reserved_1, size = 7 },
    [8] = { pfield = jpx.fields.E_reserved_2, size = 7 },
  },
  ["C"] = {},
  ["D"] = {
    [0] = { pfield = jpx.fields.D_timestamp_ns, size = 4 },
    [1] = { pfield = jpx.fields.D_order_id, size = 8 },
    [2] = { pfield = jpx.fields.D_order_book_id, size = 4 },
    [3] = { pfield = jpx.fields.D_side, size = 1 },
  },
  ["P"] = {},
  ["Z"] = {},
}

dissect.process_field = function(field, buffer, offset, size, parent)
  local range = buffer(offset, size)
  parent:add(field, range)
  return offset + size
end

dissect.message_type_field = function(buffer, offset, parent)
  local range = buffer(offset, dissect.size_of.message_type)
  parent = parent:add(jpx.fields.packet_type, range)
  return parent
end

-- Dissect: Message
dissect.process_message = function(msg_type, buffer, offset, packet, parent)
  parent = dissect.message_type_field(buffer, offset, parent)

  local fields_list = dissect.message_fields_table[msg_type]
  if #fields_list == 0 then
    return offset
  end

  offset = offset + dissect.size_of.message_type
  for i = 0, #fields_list do
    local field_obj = fields_list[i]
    offset = dissect.process_field(field_obj.pfield, buffer, offset, field_obj.size, parent)
  end

  return offset
end

dissect.message = function(buffer, offset, packet, parent)
  parent = parent:add(jpx.fields.message)

  local msg_len = buffer(offset, dissect.size_of.message_length):uint()
  offset = dissect.process_field(jpx.fields.message_length, buffer, offset, dissect.size_of.message_length, parent)

  local msg_type = buffer(offset, dissect.size_of.message_type):string()
  local next_offset = dissect.process_message(msg_type, buffer, offset, packet, parent)
  
  if next_offset == offset then
    return msg_len + offset
  else
    return next_offset
  end
end

-- Dissect: Packet Header
dissect.packet_header = function(buffer, offset, packet, parent)
  parent = parent:add(jpx.fields.packet_header)

  for i = 0, #dissect.packet_header_fields do
    local field = dissect.packet_header_fields[i]
    offset = dissect.process_field(field.pfield, buffer, offset, field.size, parent)
  end

  return offset
end

-- Dissect Packet
dissect.packet = function(buffer, packet, parent)
  local index = 0

  index = dissect.packet_header(buffer, index, packet, parent)

  while index < buffer:len() do
    index = dissect.message(buffer, index, packet, parent)
  end

  return index
end

-----------------------------------------------------------------------
-- Protocol Dissector and Components
-----------------------------------------------------------------------

-- Initialize Dissector
function jpx.init()
end

-- Dissector for JPX
function jpx.dissector(buffer, packet, parent)

  -- Set protocol name
  packet.cols.protocol = jpx.name

  -- Dissect protocol
  local protocol = parent:add(jpx, buffer(), jpx.description, "("..buffer:len().." Bytes)")
  local protocol_size = dissect.packet(buffer, packet, protocol)
end

function jpx.prefs_changed()
  if options.empty_session_id ~= jpx.prefs.empty_session_id then
    options.empty_session_id = jpx.prefs.empty_session_id
    reload()
  end
end

-- Register With Udp Table
local udp_table = DissectorTable.get("udp.port")
udp_table:add(65333, jpx)

-----------------------------------------------------------------------
-- Protocol Heuristics
-----------------------------------------------------------------------

-- Verify size of packet
verify.jpx_packet_size = function(buffer)

  return true
end

-- Verify Session ID Field
verify.session_id = function(buffer)
  local res = false

  local range = buffer(0, dissect.size_of.session_id)
  if options.empty_session_id then
    res = true
    local ar = range:bytes()
    for i = 0, (ar:len() - 1) do
      if ar:get_index(i) ~= 0 then return false end
    end

  else
    local sid = range:string():match("JP[0-9]+")
    if (sid ~= nil) and (sid:len() == dissect.size_of.session_id) then
      return true
    end
  end

  return res
end


-- Dissector Heuristic for JPX
local function jpx_heuristic(buffer, packet, parent)
  -- Verify packet length
  if not verify.jpx_packet_size(buffer) then return false end

  -- Verify Session ID
  if not verify.session_id(buffer) then return false end

  -- Protocol is valid, set conversation and dissect this packet
  packet.conversation = jpx
  jpx.dissector(buffer, packet, parent)

  return true
end

-- Register JPX Heuristic
jpx:register_heuristic("udp", jpx_heuristic)
