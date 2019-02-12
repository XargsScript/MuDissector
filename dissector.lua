
------------------------------------------------------------------
-- declare mu online port
local MU_PORT = "55901"
-- the function return mu protocol msg (c1/c2/c3/c4) length
function get_mu_protocol_mesg_len(offset,buffer)
	local msg_type = buffer(offset,1):uint()
	local len      = 0
	if  msg_type == 0xc2 or msg_type == 0xc4 then
		len = buffer(offset+1,2):uint()
	elseif msg_type == 0xc1 or msg_type == 0xc3 then
		len = buffer(offset+1,1):uint()
	end
	return len
end
------------------------------------------------------------------
------------------------------------------------------------------
-- declare mu online protocol-------------------------------------
local mu_proto = Proto("mu","MU Online protocol analysis of the TCP")
-- read reserve tcp protocol fileds
tcp_dst_f = Field.new("tcp.dstport")
tcp_src_f = Field.new("tcp.srcport")
tcp_flags = Field.new("tcp.flags")
------------------------------------------------------------------
------------------------------------------------------------------
-- dissector------------------------------------------------------
function mu_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "mu"
	local subtree  = tree:add(mu_proto,buffer(),"Mu Protocol")
	subtree:add("len:" .. buffer:len())
	local hex_msg = ''
	for s_i = 1,buffer:len() do
		hex_msg = hex_msg .. string.format("%02x",buffer(s_i-1,1):uint())
	end
	subtree:add("raw:" .. hex_msg)
	local offset = 0
	local command_count = 0
	local tcp_dst = tostring(tcp_dst_f())
	local tcp_src = tostring(tcp_src_f())
	local bf = {}
	while buffer:len() > offset do
		local msg_type = buffer(offset,1)
		local msg_len  = get_mu_protocol_mesg_len(offset,buffer)
		if msg_len > buffer:len() - offset then
			pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
			return buffer:len() - msg_len
		else
			command_count = command_count + 1
			local new_tree = subtree:add('Command ' .. command_count)
			new_tree:add(buffer(offset,1),"Command: " .. buffer(offset,1))
			new_tree:add('',"len: " .. msg_len)
			---------------
			local hex_msg = ''
			for s_i = 1	, msg_len do
				hex_msg = hex_msg .. string.format("%02x",buffer(offset+s_i-1,1):uint())
			end
			print(tcp_dst .. ',' .. hex_msg)
			new_tree:add('',"law: " .. hex_msg)
		end
		if msg_len == 0 then break end
		offset = offset + msg_len
	end
end
------------------------------------------------------------------
------------------------------------------------------------------
-- register mu protocol with tcp----------------------------------
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(MU_PORT,mu_proto)
------------------------------------------------------------------
