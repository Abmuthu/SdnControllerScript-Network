



from ryu.base import app_manager

from ryu.controller import ofp_event

import ryu.app.ofctl.api as api

from ryu.controller.handler import MAIN_DISPATCHER

from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_0

from ryu.lib.mac import haddr_to_bin

from ryu.lib.ip import ipv4_to_int

from ryu.lib.packet import packet

from ryu.lib.packet import ethernet, arp, ipv4

from ryu.lib.packet import ether_types

from ryu.lib import addrconv







class SimpleSwitch(app_manager.RyuApp):
    
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
   
    

	def __init__(self, *args, **kwargs):
        
		super(SimpleSwitch, self).__init__(*args, **kwargs)
        
		self.mac_to_port = {}

    

	def add_flow(self, datapath, in_port, src_ip, dst_ip, actions, eth):
        
		ofproto = datapath.ofproto
        
		match = datapath.ofproto_parser.OFPMatch(
            
			in_port=in_port, nw_src=ipv4_to_int(src_ip), nw_dst=ipv4_to_int(dst_ip), dl_type = 
			ether_types.ETH_TYPE_IP or ether_types.ETH_TYPE_ARP )         

		mod = datapath.ofproto_parser.OFPFlowMod(
            
		      datapath=datapath, match=match, cookie=0,
            
	              command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            
		      priority=ofproto.OFP_DEFAULT_PRIORITY,
            
	              flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        
       

		datapath.send_msg(mod) 

    

	def arp_reply(self,datapath, src, dst, dst_ip, src_ip, eth, msg):
        
		ofproto = datapath.ofproto
        
		parser = datapath.ofproto_parser
        
		pkt = packet.Packet()
        
		pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=src, src=dst))
        
		pkt.add_protocol(arp.arp(opcode=2, src_mac=dst, src_ip=dst_ip, dst_mac=src, dst_ip=src_ip))
        
		pkt.serialize()
        
		self.logger.info("packet-out %s", pkt)

        
		
		actions = [parser.OFPActionOutput(port=msg.in_port)]
        
		data = pkt.data
     
        
		out = parser.OFPPacketOut(datapath=datapath,
                                  
		      buffer_id=ofproto.OFP_NO_BUFFER,
                                  
                      in_port=ofproto.OFPP_CONTROLLER,
                                  
                      actions=actions,
                                  
                      data=data)
        
		datapath.send_msg(out)
        
                #self.logger.info("executed for dpid %s", datapath.id)

    

	def add_entry(self, datapath, in_port, src_ip, dst_ip, out_port, eth):
        
		ofproto = datapath.ofproto
        
		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
		self.add_flow(datapath, in_port, src_ip, dst_ip, actions, eth)


   

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    
	def _packet_in_handler(self, ev):
        
		msg = ev.msg
        
		datapath = msg.datapath
        
		ofproto = datapath.ofproto

        

		pkt = packet.Packet(msg.data)
        
		eth = pkt.get_protocol(ethernet.ethernet)
        
		pkt_arp = pkt.get_protocol(arp.arp)


        

		dst = eth.dst
        
		src = eth.src
        
		dpid = datapath.id
      
        
	
		datapath_s2 = api.get_datapath(self,2)
        
		datapath_s1 = api.get_datapath(self,1)

        

        

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            
			# ignore lldp packet
            
			return
        
        

		if eth.ethertype == ether_types.ETH_TYPE_ARP:
            
			self.logger.info("arp dpid %s", datapath.id)
            
			if pkt_arp.opcode == arp.ARP_REQUEST and dpid == 1:
              
				dst_ip = pkt_arp.dst_ip
              
				src_ip = pkt_arp.src_ip

              
				self.logger.info("%s sends arp request to %s through %s with opcode %s in port %s", src_ip, dst_ip, dpid, pkt_arp.opcode, msg.in_port) 
              
              
	
				self.arp_reply(datapath, src, '00:00:00:00:00:02', dst_ip, src_ip, eth, msg)
                  
          
              
				#2 entries for switch 1
              
				self.add_entry(datapath, 1, '10.0.0.1','10.0.0.2', 2, eth)
   
           			self.add_entry(datapath, 2, '10.0.0.2','10.0.0.1', 1, eth)
               
              
			
				#2 entries for switch 2
              
				datapath = datapath_s2
              
				self.add_entry(datapath, 1, '10.0.0.2','10.0.0.1', 2, eth)
              
				self.add_entry(datapath, 2, '10.0.0.1','10.0.0.2', 1, eth)

            

			if pkt_arp.opcode == arp.ARP_REQUEST and dpid == 2:
              
				dst_ip = pkt_arp.dst_ip
              
				src_ip = pkt_arp.src_ip

              
				self.logger.info("%s sends arp request to %s through %s with opcode %s in port %s", src_ip, dst_ip, dpid, pkt_arp.opcode, msg.in_port)

 
             
				self.arp_reply(datapath_s2, src, '00:00:00:00:00:01', dst_ip, src_ip, eth, msg)

     
              

				#2 entries for switch 2
              
				self.add_entry(datapath, 1, '10.0.0.2','10.0.0.1', 2, eth)
              
				self.add_entry(datapath, 2, '10.0.0.1','10.0.0.2', 1, eth)


              

				#2 entries for switch 1
              
				datapath = datapath_s1
              
				self.add_entry(datapath, 1, '10.0.0.1','10.0.0.2', 2, eth)
              
				self.add_entry(datapath, 2, '10.0.0.2','10.0.0.1', 1, eth)
       

   
